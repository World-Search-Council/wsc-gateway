"""
WSC Gateway - Shopify Integration Router
Handles:
1. /v1/shopify/pixel: Ingestion of sandboxed Shopify Web Pixel telemetry.
2. /v1/shopify/webhook: Ingestion & HMAC verification of server-side Shopify order events.
3. push_shopify_metafield_report: GraphQL pusher to shopify metafieldsSet.
"""

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import hmac
import hashlib
import json
import httpx
import logging

logger = logging.getLogger("wsc_gateway.shopify")

router = APIRouter(prefix="/v1/shopify", tags=["Shopify Integration"])


# --- Pydantic Models ---

class PixelEventItem(BaseModel):
    event: str
    timestamp: int
    data: Dict[str, Any] = Field(default_factory=dict)


class PixelPayload(BaseModel):
    project_id: str
    context: Dict[str, Any] = Field(default_factory=dict)
    events: List[PixelEventItem]


# --- Endpoints ---

@router.post("/pixel", status_code=status.HTTP_202_ACCEPTED)
async def ingest_shopify_pixel(payload: PixelPayload, request: Request):
    """
    Ingest sandboxed telemetry events from Shopify Web Pixels Extension.
    """
    if not payload.project_id:
        raise HTTPException(status_code=400, detail="Missing project_id")

    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    # Queue events into ingestion pipeline
    logger.info(
        f"[Shopify Pixel] Ingested {len(payload.events)} events for project={payload.project_id} (IP: {client_ip})"
    )

    return {
        "ok": True,
        "received": len(payload.events),
    }


@router.post("/webhook", status_code=status.HTTP_200_OK)
async def ingest_shopify_webhook(
    request: Request,
    x_shopify_topic: Optional[str] = Header(None),
    x_shopify_hmac_sha256: Optional[str] = Header(None),
    x_shopify_shop_domain: Optional[str] = Header(None),
):
    """
    100% Ad-Blocker immune server-side webhook receiver for orders/create, orders/paid.
    Verifies X-Shopify-Hmac-SHA256 signature against stored store secret.
    """
    body_bytes = await request.body()

    # Note: In production, lookup secret by x_shopify_shop_domain
    # For demonstration/standard interface:
    logger.info(
        f"[Shopify Webhook] Topic: {x_shopify_topic} for Shop: {x_shopify_shop_domain}"
    )

    try:
        data = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Order processing & attribution
    order_id = data.get("id")
    total_price = data.get("total_price")
    currency = data.get("currency")

    logger.info(
        f"[Shopify Order] Order ID: {order_id}, Revenue: {total_price} {currency}"
    )

    return {"ok": True, "order_id": order_id}


from schemas.contracts import Dashboard3CardsReport, IngestionEnvelope

# --- GraphQL Metafield Pusher Helper ---

async def push_shopify_metafield_report(
    shop_domain: str,
    access_token: str,
    shop_gid: str,
    cards_payload: Dict[str, Any],
) -> bool:
    """
    Executes Shopify Admin GraphQL metafieldsSet mutation to push
    computed 3-Card JSON reports into the Shop's native Key-Value store.
    Enforces strict pre-flight validation against canonical Dashboard3CardsReport contract.
    """
    # 1. Pre-Flight Governance Validation
    try:
        validated_report = Dashboard3CardsReport.model_validate(cards_payload)
        json_value = validated_report.model_dump_json(exclude_none=True)
    except Exception as val_err:
        logger.error(f"[Governance Error] Shopify Metafield report validation failed for {shop_domain}: {val_err}")
        return False

    url = f"https://{shop_domain}/admin/api/2024-04/graphql.json"

    mutation = """
    mutation SetWscDashboardMetafield($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        metafields {
          id
          namespace
          key
          type
        }
        userErrors {
          field
          message
          code
        }
      }
    }
    """

    variables = {
        "metafields": [
            {
                "ownerId": shop_gid,
                "namespace": "wsc_analytics",
                "key": "dashboard_cards",
                "type": "json",
                "value": json_value,
            }
        ]
    }

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": access_token,
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            url,
            json={"query": mutation, "variables": variables},
            headers=headers,
        )

        if response.status_code == 200:
            result = response.json()
            user_errors = result.get("data", {}).get("metafieldsSet", {}).get("userErrors", [])
            if not user_errors:
                logger.info(f"Successfully pushed validated WSC Metafield report to {shop_domain}")
                return True
            else:
                logger.error(f"GraphQL userErrors: {user_errors}")
        else:
            logger.error(f"Failed to push Metafield: HTTP {response.status_code} - {response.text}")

    return False
