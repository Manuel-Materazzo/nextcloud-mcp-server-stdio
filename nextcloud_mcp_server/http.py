"""Centralized HTTP client factory for Nextcloud connections.

All outbound connections to Nextcloud (API calls, OIDC endpoints) should use
these factories to ensure consistent SSL/TLS configuration from environment
variables (NEXTCLOUD_VERIFY_SSL, NEXTCLOUD_CA_BUNDLE).
"""

from typing import Any

import httpx

from .config import get_nextcloud_ssl_verify


def nextcloud_httpx_client(**kwargs: Any) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient with Nextcloud SSL settings applied.

    Reads NEXTCLOUD_VERIFY_SSL and NEXTCLOUD_CA_BUNDLE from the environment
    via ``get_nextcloud_ssl_verify()``. Caller-supplied ``verify`` kwarg
    takes precedence if explicitly provided.

    Args:
        **kwargs: Forwarded to ``httpx.AsyncClient()``.

    Returns:
        Configured ``httpx.AsyncClient``.
    """
    kwargs.setdefault("verify", get_nextcloud_ssl_verify())
    return httpx.AsyncClient(**kwargs)


def nextcloud_httpx_transport(**kwargs: Any) -> httpx.AsyncHTTPTransport:
    """Create an httpx.AsyncHTTPTransport with Nextcloud SSL settings applied.

    Used by ``NextcloudClient`` which wraps the transport in
    ``AsyncDisableCookieTransport``.

    Args:
        **kwargs: Forwarded to ``httpx.AsyncHTTPTransport()``.

    Returns:
        Configured ``httpx.AsyncHTTPTransport``.
    """
    kwargs.setdefault("verify", get_nextcloud_ssl_verify())
    return httpx.AsyncHTTPTransport(**kwargs)
