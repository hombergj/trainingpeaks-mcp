"""Minimal OAuth 2.0 endpoints for Claude.ai custom connector registration.

Claude.ai requires OAuth discovery when adding a remote MCP server via its UI.
This module implements just enough OAuth to satisfy that flow for a personal
single-user deployment:

  1. /.well-known/oauth-authorization-server  — metadata discovery
  2. /register                                 — dynamic client registration
  3. /authorize                                — auto-approve, redirect with code
  4. /token                                    — exchange code for token

No actual auth is enforced at the OAuth level.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Protocol-Version",
}


def _base_url(request: Request) -> str:
    """Derive the public base URL from the incoming request.

    Uses X-Forwarded-Proto / X-Forwarded-Host set by Railway's proxy so the
    issuer URL is always the real public HTTPS URL, never localhost.
    """
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost"
    return f"{proto}://{host}"


async def handle_preflight(request: Request) -> Response:
    return Response(status_code=204, headers=_CORS)


async def handle_metadata(request: Request) -> JSONResponse:
    """RFC 8414 Authorization Server Metadata."""
    base = _base_url(request)
    return JSONResponse(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        },
        headers={**_CORS, "Cache-Control": "no-store"},
    )


async def handle_register(request: Request) -> JSONResponse:
    """RFC 7591 Dynamic Client Registration — accepts any client."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    # Echo back redirect_uris if provided; otherwise empty list
    redirect_uris = body.get("redirect_uris", [])

    return JSONResponse(
        {
            "client_id": "claude-mcp-client",
            "client_id_issued_at": 0,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
        status_code=201,
        headers=_CORS,
    )


async def handle_authorize(request: Request) -> Response:
    """Auto-approves every authorization request and redirects with a code."""
    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", "")

    if not redirect_uri:
        return Response("Missing redirect_uri", status_code=400, headers=_CORS)

    code = secrets.token_urlsafe(32)
    params: dict[str, str] = {"code": code}
    if state:
        params["state"] = state

    return RedirectResponse(
        url=f"{redirect_uri}?{urlencode(params)}",
        status_code=302,
        headers=_CORS,
    )


async def handle_token(request: Request) -> JSONResponse:
    """Issues a bearer token for any presented code."""
    return JSONResponse(
        {
            "access_token": secrets.token_urlsafe(32),
            "token_type": "Bearer",
            "expires_in": 86400 * 365,
        },
        headers=_CORS,
    )


OAUTH_ROUTES: list[Route] = [
    Route("/.well-known/oauth-authorization-server", handle_metadata, methods=["GET", "OPTIONS"]),
    Route("/register", handle_register, methods=["POST", "OPTIONS"]),
    Route("/authorize", handle_authorize, methods=["GET", "OPTIONS"]),
    Route("/token", handle_token, methods=["POST", "OPTIONS"]),
]
