"""
WSC Gateway — Distributed Redis Cache & Redis Cluster Adapter (Prio 5.1)
Supports both standalone Redis (`REDIS_URL`) and multi-node Redis Cluster
(`REDIS_CLUSTER_MODE=true` / `REDIS_CLUSTER_NODES=host1:6379,host2:6379`)
with bounded in-memory L1 failover protection so Gateway requests never fail
during Redis Cluster slot migrations or transient network partitions.
"""

import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

import redis.asyncio as redis
from redis.asyncio.cluster import ClusterNode, RedisCluster

logger = logging.getLogger("wsc_gateway.redis_cache")


class WscRedisCache:
    """
    Drop-in async Redis / RedisCluster client wrapper with L1 TTL failover cache.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        cluster_mode: bool = False,
        cluster_nodes: str = "",
        l1_max_entries: int = 2048,
    ):
        self.redis_url = (redis_url or os.getenv("REDIS_URL") or "redis://redis:6379/0").strip()
        self.cluster_mode = cluster_mode or (
            os.getenv("REDIS_CLUSTER_MODE", "false").strip().lower() in ("1", "true", "yes")
        ) or bool((cluster_nodes or os.getenv("REDIS_CLUSTER_NODES", "")).strip())
        self.cluster_nodes_raw = (cluster_nodes or os.getenv("REDIS_CLUSTER_NODES", "")).strip()
        self.l1_max_entries = l1_max_entries
        self._l1: Dict[str, Tuple[float, str]] = {}
        self._client: Any = None
        self.mode_label = "cluster" if self.cluster_mode else "standalone"

    def connect(self) -> "WscRedisCache":
        """Initializes the underlying standalone Redis or RedisCluster client."""
        try:
            if self.cluster_mode:
                startup_nodes = []
                if self.cluster_nodes_raw:
                    for item in self.cluster_nodes_raw.split(","):
                        item = item.strip()
                        if not item:
                            continue
                        if "://" in item:
                            # Support full redis://host:port URLs inside REDIS_CLUSTER_NODES
                            host_part = item.split("://", 1)[1].split("/", 1)[0]
                        else:
                            host_part = item
                        if ":" in host_part:
                            h, p = host_part.rsplit(":", 1)
                            startup_nodes.append(ClusterNode(h.strip(), int(p.strip())))
                        else:
                            startup_nodes.append(ClusterNode(host_part.strip(), 6379))

                if startup_nodes:
                    password = os.getenv("REDIS_PASSWORD") or None
                    self._client = RedisCluster(
                        startup_nodes=startup_nodes,
                        password=password,
                        decode_responses=True,
                        socket_connect_timeout=3.0,
                        socket_timeout=3.0,
                        health_check_interval=30,
                    )
                else:
                    self._client = RedisCluster.from_url(
                        self.redis_url,
                        decode_responses=True,
                        socket_connect_timeout=3.0,
                        socket_timeout=3.0,
                        health_check_interval=30,
                    )
                logger.info("Initialized WSC Redis client in CLUSTER mode.")
            else:
                self._client = redis.from_url(
                    self.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=3.0,
                    socket_timeout=3.0,
                    health_check_interval=30,
                )
                logger.info("Initialized WSC Redis client in STANDALONE mode.")
        except Exception as exc:
            logger.warning(f"Redis client initialization failed ({exc}); operating on L1 failover cache.")
            self._client = None
        return self

    def _l1_get(self, key: str) -> Optional[str]:
        entry = self._l1.get(key)
        if not entry:
            return None
        expires_at, val = entry
        if expires_at < time.monotonic():
            self._l1.pop(key, None)
            return None
        return val

    def _l1_set(self, key: str, value: str, ex: Optional[int] = None) -> None:
        if len(self._l1) >= self.l1_max_entries:
            now = time.monotonic()
            expired = [k for k, (exp, _) in self._l1.items() if exp < now]
            for k in expired:
                self._l1.pop(k, None)
            if len(self._l1) >= self.l1_max_entries:
                # Evict oldest inserted key
                oldest_key = next(iter(self._l1), None)
                if oldest_key is not None:
                    self._l1.pop(oldest_key, None)
        ttl = min(int(ex or 300), 900)  # Cap L1 TTL at 15m so cluster invalidations propagate promptly
        self._l1[key] = (time.monotonic() + ttl, str(value))

    @property
    def l1_size(self) -> int:
        return len(self._l1)

    async def get(self, key: str) -> Optional[str]:
        if self._client is not None:
            try:
                val = await self._client.get(key)
                if val is not None:
                    self._l1_set(key, val, ex=300)
                return val
            except Exception as exc:
                logger.warning(f"Redis GET fallback to L1 for '{key}': {exc}")
        return self._l1_get(key)

    async def set(self, key: str, value: Any, ex: Optional[int] = None, **kwargs) -> bool:
        str_val = value if isinstance(value, str) else str(value)
        self._l1_set(key, str_val, ex=ex)
        if self._client is not None:
            try:
                await self._client.set(key, str_val, ex=ex, **kwargs)
                return True
            except Exception as exc:
                logger.warning(f"Redis SET fallback to L1 only for '{key}': {exc}")
        return False

    async def delete(self, *keys: str) -> int:
        for k in keys:
            self._l1.pop(k, None)
        if self._client is not None and keys:
            try:
                return int(await self._client.delete(*keys))
            except Exception as exc:
                logger.warning(f"Redis DELETE error for {keys}: {exc}")
        return 0

    async def ping(self) -> bool:
        if self._client is None:
            return False
        try:
            res = await self._client.ping()
            return bool(res)
        except Exception:
            return False

    async def close(self) -> None:
        if self._client is not None:
            try:
                if hasattr(self._client, "aclose"):
                    await self._client.aclose()
                else:
                    await self._client.close()
            except Exception:
                pass


def create_async_redis_client() -> WscRedisCache:
    """Factory used by FastAPI startup lifecycle."""
    return WscRedisCache().connect()
