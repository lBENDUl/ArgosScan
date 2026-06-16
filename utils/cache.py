"""
ArgosScan - Simple file-based cache (TTL-aware)
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("argosScan.cache")

CACHE_FILE = Path(".argosScan_cache.json")


def _load() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    try:
        CACHE_FILE.write_text(json.dumps(data, indent=2, default=str))
    except OSError as e:
        logger.warning(f"Cache write failed: {e}")


def cache_get(key: str) -> Optional[Any]:
    """
    Retrieve a cached value.

    Returns:
        The cached value, or None if missing / expired.
    """
    data = _load()
    entry = data.get(key)
    if not entry:
        return None

    try:
        expires = datetime.fromisoformat(entry["expires"])
        # Make naive datetimes UTC-aware for comparison
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires:
            logger.debug(f"Cache miss (expired): {key}")
            return None
    except (KeyError, ValueError):
        return None

    logger.debug(f"Cache hit: {key}")
    return entry.get("value")


def cache_set(key: str, value: Any, ttl: int = 86400) -> None:
    """
    Store a value in the cache.

    Args:
        key:   Cache key.
        value: JSON-serialisable value.
        ttl:   Time-to-live in seconds (default: 24 h).
    """
    data = _load()
    data[key] = {
        "value": value,
        "expires": (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat(),
    }
    _save(data)
    logger.debug(f"Cache set: {key} (TTL={ttl}s)")


def cache_clear() -> None:
    """Remove all cached entries."""
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()
    logger.debug("Cache cleared")
