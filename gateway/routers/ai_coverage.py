"""
WSC Gateway - AI Coverage & URL Inspector Router
Provides authenticated endpoints for querying AI Bot visibility, Live RAG visits,
and Training Scraper metrics across both client-owned and external third-party domains.
"""

from fastapi import APIRouter, Header, HTTPException, Request, status
import hmac
import hashlib
import json
import time
from urllib.parse import urlparse
import tldextract
import logging

from schemas.contracts import (
    AiCoverageQueryRequest,
    AiCoverageQueryResponse,
    QueryParsedContext,
    UrlMetrics,
    BotMetrics,
    BotHitDetail,
    DomainCoverageMetrics
)

logger = logging.getLogger("wsc_gateway.ai_coverage")

router = APIRouter(prefix="/v1/ai-coverage", tags=["AI Coverage"])


def _human_time_diff(timestamp: int) -> str:
    if not timestamp:
        return "never"
    diff = int(time.time()) - timestamp
    if diff < 60:
        return "gerade eben"
    elif diff < 3600:
        mins = diff // 60
        return f"vor {mins} Minute{'n' if mins != 1 else ''}"
    elif diff < 86400:
        hours = diff // 3600
        return f"vor {hours} Stunde{'n' if hours != 1 else ''}"
    else:
        days = diff // 86400
        return f"vor {days} Tag{'en' if days != 1 else ''}"


def _canonicalize_query(query: str, project_domain: str):
    """
    Extracts root_domain, url_path, and determines if it's a cross-domain query.
    """
    raw = query.strip()
    is_cross_domain = False
    
    if not raw.startswith("http://") and not raw.startswith("https://"):
        if "/" in raw and not raw.startswith("/"):
            # e.g. "partner.com/article"
            raw = "https://" + raw
        elif raw.startswith("/"):
            # relative path on project's own domain
            raw = project_domain.rstrip("/") + raw
        else:
            # bare domain e.g. "techcrunch.com"
            raw = "https://" + raw

    parsed = urlparse(raw)
    host = parsed.netloc.lower()
    url_path = parsed.path if parsed.path else "/"
    
    # Extract root domain (e.g., example.co.uk -> example.co.uk, www.shop.de -> shop.de)
    ext = tldextract.extract(raw)
    if ext.domain and ext.suffix:
        root_domain = f"{ext.domain}.{ext.suffix}".lower()
    else:
        root_domain = host

    # Compare against project root domain
    proj_ext = tldextract.extract(project_domain)
    proj_root = f"{proj_ext.domain}.{proj_ext.suffix}".lower() if (proj_ext.domain and proj_ext.suffix) else project_domain.lower()
    
    if root_domain != proj_root:
        is_cross_domain = True

    return QueryParsedContext(
        raw=query,
        root_domain=root_domain,
        url_path=url_path,
        is_cross_domain=is_cross_domain
    )


@router.post("/query", response_model=AiCoverageQueryResponse)
async def query_ai_coverage(
    payload: AiCoverageQueryRequest,
    request: Request,
    x_wsc_sig: str = Header(None)
):
    """
    Query AI Coverage metrics for a specific URL or domain across the WSC sensor network.
    Authenticated via project api_secret and HMAC-SHA256.
    """
    if not x_wsc_sig:
        raise HTTPException(status_code=401, detail="Missing X-WSC-Sig Header")

    # Access app dependencies
    redis_client = request.app.state.redis if hasattr(request.app.state, "redis") else None
    db_pool = request.app.state.db_pool if hasattr(request.app.state, "db_pool") else None
    ch_client = getattr(request.app.state, "clickhouse", None)

    # 1. Project Authentication
    project_uuid = payload.project_id
    project_data = None

    if redis_client:
        cached = await redis_client.get(f"project:{project_uuid}")
        if cached:
            project_data = json.loads(cached)

    if not project_data and db_pool:
        import aiomysql
        async with db_pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute("SELECT api_secret, domain, status FROM projects WHERE uuid = %s", (project_uuid,))
                row = await cur.fetchone()
                if row:
                    project_data = row

    if not project_data:
        raise HTTPException(status_code=404, detail="Project not registered")

    if project_data.get("status") == 999:
        raise HTTPException(status_code=403, detail="Project suspended")

    # Verify HMAC
    raw_body = await request.body()
    expected_sig = hmac.new(
        project_data["api_secret"].encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, x_wsc_sig):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")

    # 2. Canonicalize Target Query
    project_domain = project_data.get("domain", "")
    query_ctx = _canonicalize_query(payload.query, project_domain)

    # 3. Query ClickHouse Analytics (or fallback heuristic if DB connection offline)
    url_metrics = UrlMetrics(is_known_in_network=False)
    domain_coverage = DomainCoverageMetrics(root_domain=query_ctx.root_domain)

    if ch_client:
        try:
            # Query Domain Level Coverage
            dom_query = """
                SELECT
                    uniq(url_path) as known_urls,
                    uniqIf(url_path, event_type = 'bot_hit' AND bot_category = 'ai') as ai_urls,
                    uniqIf(url_path, event_type = 'bot_hit' AND bot_type = 'rag') as rag_urls,
                    uniqIf(url_path, event_type = 'bot_hit' AND bot_type = 'training') as training_urls
                FROM wsc_analytics_raw
                WHERE root_domain = %(dom)s
                  AND timestamp >= now() - INTERVAL 30 DAY
            """
            dom_row = ch_client.query(dom_query, parameters={"dom": query_ctx.root_domain}).first_row
            if dom_row and dom_row[0] > 0:
                known = int(dom_row[0])
                ai_urls = int(dom_row[1])
                rag_urls = int(dom_row[2])
                train_urls = int(dom_row[3])
                
                domain_coverage = DomainCoverageMetrics(
                    root_domain=query_ctx.root_domain,
                    known_urls_count=known,
                    ai_covered_urls_count=ai_urls,
                    ai_coverage_pct=round((ai_urls / known) * 100, 1) if known else 0.0,
                    rag_coverage_pct=round((rag_urls / known) * 100, 1) if known else 0.0,
                    training_coverage_pct=round((train_urls / known) * 100, 1) if known else 0.0,
                    network_confidence="high" if known > 50 else "medium" if known > 5 else "low"
                )

            # Query Specific URL Metrics
            url_query = """
                SELECT
                    count() as total_hits,
                    countIf(event_type = 'bot_hit' AND bot_type = 'rag' AND timestamp >= now() - INTERVAL 7 DAY) as rag_7d,
                    countIf(event_type = 'bot_hit' AND bot_type = 'rag' AND timestamp >= now() - INTERVAL 30 DAY) as rag_30d,
                    maxIf(toUnixTimestamp(timestamp), event_type = 'bot_hit' AND bot_type = 'rag') as last_rag,
                    countIf(event_type = 'bot_hit' AND bot_type = 'training' AND timestamp >= now() - INTERVAL 7 DAY) as train_7d,
                    countIf(event_type = 'bot_hit' AND bot_type = 'training' AND timestamp >= now() - INTERVAL 30 DAY) as train_30d,
                    maxIf(toUnixTimestamp(timestamp), event_type = 'bot_hit' AND bot_type = 'training') as last_train
                FROM wsc_analytics_raw
                WHERE root_domain = %(dom)s
                  AND url_path = %(path)s
                  AND timestamp >= now() - INTERVAL 30 DAY
            """
            url_row = ch_client.query(url_query, parameters={"dom": query_ctx.root_domain, "path": query_ctx.url_path}).first_row
            
            if url_row and url_row[0] > 0:
                last_rag = int(url_row[3] or 0)
                last_train = int(url_row[6] or 0)
                
                # Fetch top bots for this URL
                top_bots_query = """
                    SELECT bot_type, bot_name, count() as cnt
                    FROM wsc_analytics_raw
                    WHERE root_domain = %(dom)s
                      AND url_path = %(path)s
                      AND event_type = 'bot_hit'
                      AND timestamp >= now() - INTERVAL 30 DAY
                    GROUP BY bot_type, bot_name
                    ORDER BY cnt DESC
                    LIMIT 10
                """
                top_rows = ch_client.query(top_bots_query, parameters={"dom": query_ctx.root_domain, "path": query_ctx.url_path}).result_rows
                
                top_rag = []
                top_train = []
                for b_type, b_name, cnt in top_rows:
                    if b_type == "rag":
                        top_rag.append(BotHitDetail(name=b_name, hits=int(cnt)))
                    elif b_type == "training":
                        top_train.append(BotHitDetail(name=b_name, hits=int(cnt)))

                url_metrics = UrlMetrics(
                    is_known_in_network=True,
                    total_hits_30d=int(url_row[0]),
                    rag=BotMetrics(
                        visited=int(url_row[2]) > 0,
                        hits_7d=int(url_row[1]),
                        hits_30d=int(url_row[2]),
                        last_seen=last_rag if last_rag > 0 else None,
                        last_seen_human=_human_time_diff(last_rag),
                        top_bots=top_rag
                    ),
                    training=BotMetrics(
                        visited=int(url_row[5]) > 0,
                        hits_7d=int(url_row[4]),
                        hits_30d=int(url_row[5]),
                        last_seen=last_train if last_train > 0 else None,
                        last_seen_human=_human_time_diff(last_train),
                        top_bots=top_train
                    )
                )

        except Exception as e:
            logger.error(f"ClickHouse AI Coverage query failed: {e}")
            # Fallback to graceful response

    return AiCoverageQueryResponse(
        status="success",
        query=query_ctx,
        url_metrics=url_metrics,
        domain_coverage=domain_coverage
    )
