"""
Shared HTTP helpers with a realistic User-Agent and rate limiting.
"""

from __future__ import annotations

import warnings
from typing import Any, Dict, Optional

import httpx
import requests
import urllib3

from backend.core.config import settings
from backend.core.rate_limiter import RateLimiter, default_limiter

# Soften noise when verify=False is used for recon against odd lab certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def _headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    headers = {"User-Agent": settings.user_agent, "Accept": "*/*"}
    if extra:
        headers.update(extra)
    return headers


def http_get(
    url: str,
    *,
    timeout: Optional[float] = None,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
    limiter: Optional[RateLimiter] = None,
    verify: bool = True,
) -> requests.Response:
    """Synchronous GET with rate limit + SAQRIntel User-Agent."""
    (limiter or default_limiter).wait()
    return requests.get(
        url,
        timeout=timeout or settings.http_timeout,
        headers=_headers(headers),
        allow_redirects=allow_redirects,
        verify=verify,
    )


def http_head(
    url: str,
    *,
    timeout: Optional[float] = None,
    limiter: Optional[RateLimiter] = None,
    verify: bool = True,
) -> requests.Response:
    (limiter or default_limiter).wait()
    return requests.head(
        url,
        timeout=timeout or settings.http_timeout,
        headers=_headers(),
        allow_redirects=True,
        verify=verify,
    )


async def async_http_get(url: str, **kwargs: Any) -> httpx.Response:
    """Async GET for FastAPI routes that need non-blocking HTTP."""
    timeout = kwargs.pop("timeout", settings.http_timeout)
    async with httpx.AsyncClient(
        timeout=timeout,
        headers=_headers(),
        follow_redirects=True,
    ) as client:
        return await client.get(url, **kwargs)
