"""
WSC Ecosystem Canonical Data Contracts & Pydantic Validation Models
Standard Version: 1.5.0
"""

from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Any, Optional, Literal


# --- Telemetry Ingestion Event Models ---

class EventMetadata(BaseModel):
    # Purchase Metadata
    order_id: Optional[str] = None
    order_number: Optional[str] = None
    amount_total: Optional[float] = None
    amount_net: Optional[float] = None
    shipping_total: Optional[float] = None
    tax_total: Optional[float] = None
    currency: Optional[str] = None
    items_count: Optional[int] = None
    items: Optional[List[Dict[str, Any]]] = None
    source: Optional[str] = None

    # Bot Hit Metadata
    bot_name: Optional[str] = None
    bot_category: Optional[Literal["ai", "search", "seo_tool", "other"]] = None
    bot_type: Optional[Literal["rag", "training", "search", "seo_tool", "other"]] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None

    # Client Metadata
    title: Optional[str] = None
    lang: Optional[str] = None
    screen: Optional[str] = None
    href: Optional[str] = None
    duration_ms: Optional[int] = None
    final: Optional[bool] = None

    class Config:
        extra = "allow"


class WscEvent(BaseModel):
    t: int = Field(..., description="Unix timestamp in seconds")
    e: Literal[
        "pageview",
        "purchase",
        "bot_hit",
        "click",
        "download",
        "time_on_page",
        "view_item",
        "add_to_cart",
        "custom"
    ]
    p: str = Field(default="/", max_length=2048)
    r: Optional[str] = Field(default="")
    m: Dict[str, Any] = Field(default_factory=dict)


class IngestionEnvelope(BaseModel):
    events: List[WscEvent]


# --- 3-Card Dashboard Canonical Report Models ---

class ChannelsBreakdown(BaseModel):
    ai_pct: float = Field(..., ge=0.0, le=100.0)
    search_pct: float = Field(..., ge=0.0, le=100.0)
    social_pct: float = Field(..., ge=0.0, le=100.0)
    direct_pct: float = Field(..., ge=0.0, le=100.0)
    referral_pct: float = Field(..., ge=0.0, le=100.0)


class Card1Metrics(BaseModel):
    visitors: int = Field(..., ge=0)
    pageviews: int = Field(..., ge=0)
    avg_engaged_time: str
    orders: int = Field(..., ge=0)
    revenue: float = Field(..., ge=0.0)
    currency: str = Field(..., min_length=3, max_length=3)
    channels: ChannelsBreakdown


class Card1Payload(BaseModel):
    data_7d: Card1Metrics
    data_30d: Card1Metrics


class InsightAction(BaseModel):
    type: Literal["opportunity", "warning", "action"]
    title: str
    description: str
    impact: Literal["high", "medium", "low"]


class Card2Metrics(BaseModel):
    summary: str
    actions: List[InsightAction] = Field(default_factory=list)


class Card2Payload(BaseModel):
    data_7d: Card2Metrics
    data_30d: Card2Metrics


class Card3Metrics(BaseModel):
    human_pct: float = Field(..., ge=0.0, le=100.0)
    bot_pct: float = Field(..., ge=0.0, le=100.0)
    ai_rag_hits: int = Field(..., ge=0)
    ai_training_hits: int = Field(..., ge=0)
    search_hits: int = Field(..., ge=0)


class Card3Payload(BaseModel):
    data_7d: Card3Metrics
    data_30d: Card3Metrics


class Dashboard3CardsReport(BaseModel):
    version: str = Field(default="1.5.0")
    updated_at: int
    project_id: Optional[str] = None
    shop_id: Optional[str] = None
    card1: Card1Payload
    card2: Card2Payload
    card3: Card3Payload


class ShopifyMetafieldReport(BaseModel):
    namespace: str = Field(default="wsc_analytics")
    key: str = Field(default="dashboard_cards")
    type: str = Field(default="json")
    value: str


# ==========================================
# 3. AI COVERAGE & URL INSPECTION CONTRACTS
# ==========================================

class AiCoverageQueryRequest(BaseModel):
    project_id: str
    query: str
    timeframe: Literal["7d", "30d"] = "30d"


class BotHitDetail(BaseModel):
    name: str
    hits: int


class BotMetrics(BaseModel):
    visited: bool = False
    hits_7d: int = 0
    hits_30d: int = 0
    last_seen: Optional[int] = None
    last_seen_human: str = "never"
    top_bots: List[BotHitDetail] = Field(default_factory=list)


class UrlMetrics(BaseModel):
    is_known_in_network: bool = False
    total_hits_30d: int = 0
    rag: BotMetrics = Field(default_factory=BotMetrics)
    training: BotMetrics = Field(default_factory=BotMetrics)


class DomainCoverageMetrics(BaseModel):
    root_domain: str
    known_urls_count: int = 0
    ai_covered_urls_count: int = 0
    ai_coverage_pct: float = 0.0
    rag_coverage_pct: float = 0.0
    training_coverage_pct: float = 0.0
    network_confidence: Literal["high", "medium", "low", "none"] = "none"


class QueryParsedContext(BaseModel):
    raw: str
    root_domain: str
    url_path: str
    is_cross_domain: bool = False


class AiCoverageQueryResponse(BaseModel):
    status: Literal["success", "not_found", "error"] = "success"
    query: QueryParsedContext
    url_metrics: UrlMetrics
    domain_coverage: DomainCoverageMetrics


# ==========================================
# 5. Industry Benchmark Intelligence Contracts
# ==========================================

class BenchmarkMetricItem(BaseModel):
    site_val: float
    industry_median: float
    industry_p75: Optional[float] = None
    industry_p90: Optional[float] = None
    delta_pct: float
    rating: Literal["top_10", "above_average", "average", "below_average"]
    badge: str


class BenchmarkReportData(BaseModel):
    status: Literal["active", "pending_k_threshold", "unclassified"] = "active"
    vertical: str = ""
    vertical_label: str = ""
    nodes_in_benchmark: int = 0
    k_threshold_satisfied: bool = False
    metrics: Dict[str, BenchmarkMetricItem] = Field(default_factory=dict)


class VerticalClassificationRequest(BaseModel):
    project_id: str
    url: Optional[str] = ""
    title: Optional[str] = ""
    meta_description: Optional[str] = ""
    keywords: Optional[str] = ""
    sample_text: Optional[str] = ""


class VerticalClassificationResponse(BaseModel):
    status: Literal["success", "error"] = "success"
    vertical: str
    vertical_label: str
    confidence: float
    method: Literal["nlp_centroid", "google_nlp_api", "manual", "rule_fallback"] = "nlp_centroid"
    k_anonymity_status: Literal["active", "pending_k_threshold"] = "pending_k_threshold"
    active_nodes_in_vertical: int = 0


# ==========================================
# 5. DOMAIN & TECH HEALTH SENTINEL CONTRACTS
# ==========================================

class DomainHealthSummary(BaseModel):
    overall_health: Literal["GOOD", "OK", "LOW", "PROBLEM", "ERROR", "UNCONFIGURED"] = "OK"
    ssl_status: Literal["OK", "EXPIRES_SOON", "ERROR"] = "OK"
    ssl_days_left: int = 0
    mail_health: Literal["GOOD", "OK", "LOW", "PROBLEM", "ERROR", "UNCONFIGURED"] = "OK"
    web_health: Literal["GOOD", "OK", "LOW", "PROBLEM", "ERROR", "UNCONFIGURED"] = "OK"
    dns_health: Literal["GOOD", "OK", "LOW", "PROBLEM", "ERROR", "UNCONFIGURED"] = "OK"
    headers_score: str = "0/6"


class MailSecurityContract(BaseModel):
    provider: str = "Self-hosted"
    mx_status: Literal["OK", "LOW", "PROBLEM", "N/A"] = "OK"
    spf_status: Literal["OK", "ERROR", "N/A"] = "OK"
    dkim_status: Literal["OK", "PROBLEM", "N/A"] = "OK"
    dmarc_status: Literal["GOOD", "OK", "PROBLEM", "N/A"] = "OK"
    dmarc_policy: Literal["reject", "quarantine", "none", "missing"] = "none"


class WebSecurityContract(BaseModel):
    http_to_https: Literal["OK", "PROBLEM", "N/A"] = "OK"
    www_canonicalization: Literal["OK", "PROBLEM", "N/A"] = "OK"
    canonical_url: str = ""
    hsts_enabled: Literal["GOOD", "PROBLEM", "N/A"] = "PROBLEM"
    ipv6_accessible: Literal["Yes", "No"] = "No"


class SecurityHeadersContract(BaseModel):
    score: int = Field(default=0, ge=0, le=6)
    total: int = 6
    hsts: bool = False
    csp: bool = False
    x_frame_options: bool = False
    x_content_type_options: bool = False
    referrer_policy: bool = False
    permissions_policy: bool = False


class DnsSecurityContract(BaseModel):
    dnssec_status: Literal["GOOD", "PROBLEM", "NOT_CONFIGURED"] = "NOT_CONFIGURED"
    nameserver_count: int = 0


class DomainHealthReport(BaseModel):
    project_id: str
    domain: str
    last_scan_at: int
    last_change_at: int
    days_since_change: int = 0
    drift_status: Literal["NO_CHANGE", "CHANGED", "NEW_RECORD", "DB_ERROR"] = "NO_CHANGE"
    score: int = Field(default=85, ge=0, le=100)
    rating: str = Field(default="GOOD")
    summary: DomainHealthSummary
    mail_security: MailSecurityContract
    web_security: WebSecurityContract
    security_headers: SecurityHeadersContract
    dns_security: DnsSecurityContract
    identified_services: List[str] = Field(default_factory=list)
    action_items: List[Dict[str, Any]] = Field(default_factory=list)


class SentinelScanRequest(BaseModel):
    project_id: str
    domain: Optional[str] = None
    sync: bool = False


class SentinelScanResponse(BaseModel):
    status: Literal["success", "error", "queued"] = "success"
    task_id: Optional[str] = None
    message: Optional[str] = None
    report: Optional[DomainHealthReport] = None


# ==========================================
# 5. PAGESPEED & CORE WEB VITALS CONTRACTS
# ==========================================

class PageSpeedMetricContract(BaseModel):
    name: str
    value: float
    unit: str
    rating: Literal["GOOD", "NEEDS_IMPROVEMENT", "POOR"] = "GOOD"
    description: str


class PageSpeedActionItemContract(BaseModel):
    id: str
    category: str
    severity: Literal["HIGH", "MEDIUM", "LOW", "INFO"] = "MEDIUM"
    title: str
    description: str
    potential_savings: Optional[str] = None


class PageSpeedAssetSummaryContract(BaseModel):
    total_requests: int
    total_weight_kb: float
    breakdown_kb: Dict[str, float]
    dom_nodes: int = 0
    large_images: List[Dict[str, Any]] = Field(default_factory=list)


class PageSpeedRagReadinessContract(BaseModel):
    score: float = 0.0
    status: Literal["SUPER_TURBO", "ACCEPTABLE", "BLINDSPOT"] = "ACCEPTABLE"
    effective_latency_ms: float = 0.0
    ttfb_ms: float = 0.0
    html_download_ms: float = 0.0
    delivery_time_ms: float = 0.0
    nojs_ratio: float = 1.0
    token_efficiency: float = 1.0
    bytes_raw_html: int = 0
    bytes_text: int = 0


class PageSpeedHumanUxContract(BaseModel):
    score: int = 0
    status: Literal["GOOD", "NEEDS_IMPROVEMENT", "POOR"] = "GOOD"
    lcp_ms: float = 0.0
    cls_score: float = 0.0
    tbt_ms: float = 0.0
    fcp_ms: float = 0.0


class PageSpeedAuditReport(BaseModel):
    model_config = {"extra": "ignore"}

    status: Literal["success", "error"] = "success"
    project_id: Optional[str] = None
    url: str
    strategy: Literal["mobile", "desktop"] = "mobile"
    performance_score: int = Field(default=85, ge=0, le=100)
    overall_rating: Literal["GOOD", "NEEDS_IMPROVEMENT", "POOR"] = "GOOD"
    metrics: Dict[str, PageSpeedMetricContract]
    rag_readiness: Optional[PageSpeedRagReadinessContract] = None
    human_ux: Optional[PageSpeedHumanUxContract] = None
    asset_summary: PageSpeedAssetSummaryContract
    action_items: List[PageSpeedActionItemContract] = Field(default_factory=list)
    audited_at: int


class PageSpeedAuditRequest(BaseModel):
    project_id: str
    url: Optional[str] = None
    strategy: Literal["mobile", "desktop"] = "mobile"
    sync: Optional[bool] = False


class PageSpeedAuditResponse(BaseModel):
    status: Literal["success", "queued", "error", "no_data"] = "success"
    task_id: Optional[str] = None
    message: Optional[str] = None
    report: Optional[PageSpeedAuditReport] = None
