"""
WSC Internal Services Client SDK
Provides asynchronous client wrappers for the WSC Headless Browser,
Spam & Content Classifier, and Multilingual Sentiment Engine.
"""

import os
import logging
from typing import Dict, Any, List, Optional
import aiohttp

import os
import logging
from typing import Dict, Any, List, Optional
import itertools
import aiohttp

logger = logging.getLogger("wsc-services-client")

def get_headless_servers() -> List[str]:
    raw = os.getenv("WSC_HEADLESS_SERVERS") or os.getenv("WSC_HEADLESS_URL") or "http://127.0.0.1:8081"
    servers = [s.strip().rstrip('/') for s in raw.split(",") if s.strip()]
    return servers if servers else ["http://127.0.0.1:8081"]

_server_index = 0

def get_next_headless_server() -> str:
    global _server_index
    servers = get_headless_servers()
    server = servers[_server_index % len(servers)]
    _server_index = (_server_index + 1) % len(servers)
    return server

HEADLESS_API_KEY = os.getenv("WSC_HEADLESS_API_KEY", "wsc-headless-secret-key")

SPAM_URL = os.getenv("WSC_SPAM_URL", "http://localhost:8082")
SPAM_API_KEY = os.getenv("WSC_SPAM_API_KEY", "wsc-spam-secret-key")

SENTIMENT_URL = os.getenv("WSC_SENTIMENT_URL", "http://localhost:8083")
SENTIMENT_API_KEY = os.getenv("WSC_SENTIMENT_API_KEY", "wsc-sentiment-secret-key")


class WSCServicesClient:
    """Async client for orchestrating WSC internal microservices across server clusters."""

    @staticmethod
    async def render_visual_snapshot(
        url: str,
        viewport_width: int = 1920,
        viewport_height: int = 1080,
        full_page: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Captures a clean screenshot with automatic cookie consent bypass with cluster failover."""
        servers = get_headless_servers()
        payload = {
            "url": url,
            "viewport_width": viewport_width,
            "viewport_height": viewport_height,
            "full_page": full_page
        }
        headers = {"X-API-KEY": HEADLESS_API_KEY}

        for server in servers:
            endpoint = f"{server}/render.png"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(endpoint, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        logger.warning(f"Headless server {server} returned HTTP {resp.status}")
            except Exception as e:
                logger.warning(f"Headless server {server} unreachable: {e}. Trying next server in pool...")
        return None

    @staticmethod
    async def audit_ad_density(url: str) -> Optional[Dict[str, Any]]:
        """Detects ad trackers, banners, and cosmetic ad elements on a given URL."""
        endpoint = f"{HEADLESS_URL}/detect_ads"
        payload = {"url": url}
        headers = {"X-API-KEY": HEADLESS_API_KEY}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=35)) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            logger.error(f"Error invoking ad detection service: {e}")
        return None

    @staticmethod
    async def classify_ugc_comment(
        content: str,
        author: str = "",
        email: str = "",
        threshold: float = 0.55
    ) -> Dict[str, Any]:
        """Validates a blog comment or customer review against spam patterns."""
        endpoint = f"{SPAM_URL}/v1/classify/ugc"
        payload = {
            "content": content,
            "author": author,
            "email": email,
            "threshold": threshold
        }
        headers = {"X-API-KEY": SPAM_API_KEY}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            logger.error(f"Error invoking spam classifier: {e}")

        # Graceful fallback: Allow comment if service is unreachable
        return {"is_spam": False, "action": "allow", "confidence": 0.0, "reasons": ["Service offline fallback"]}

    @staticmethod
    async def analyze_sentiment(text: str) -> Optional[Dict[str, Any]]:
        """Performs sentence-level trajectory sentiment analysis."""
        endpoint = f"{SENTIMENT_URL}/v1/analyze"
        payload = {"text": text}
        headers = {"X-API-KEY": SENTIMENT_API_KEY}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            logger.error(f"Error invoking sentiment analysis service: {e}")
        return None

    @staticmethod
    async def analyze_reviews_batch(reviews: List[str]) -> Optional[Dict[str, Any]]:
        """Calculates NPS-style sentiment index for customer reviews."""
        endpoint = f"{SENTIMENT_URL}/v1/analyze/reviews"
        payload = {"reviews": reviews}
        headers = {"X-API-KEY": SENTIMENT_API_KEY}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            logger.error(f"Error invoking review sentiment batch: {e}")
        return None

    @staticmethod
    async def audit_pagespeed(
        url: str,
        strategy: str = "mobile",
        throttle_cpu: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Executes a Core Web Vitals lab audit via the Headless Browser SpeedSentinel cluster."""
        servers = get_headless_servers()
        payload = {
            "url": url,
            "strategy": strategy,
            "throttle_cpu": throttle_cpu
        }
        headers = {"X-API-KEY": HEADLESS_API_KEY}

        for server in servers:
            endpoint = f"{server}/v1/audit/speed"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(endpoint, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=45)) as resp:
                        if resp.status == 200:
                            return await resp.json()
                        logger.warning(f"Headless SpeedSentinel server {server} failed with HTTP {resp.status}")
            except Exception as e:
                logger.warning(f"Headless SpeedSentinel server {server} unreachable: {e}. Trying next server in cluster...")
        logger.error(f"All configured headless servers ({servers}) failed for {url}")
        return None

