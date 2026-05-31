"""Minimal OAuth 2.0 endpoints for Claude.ai custom connector registration.

Claude.ai requires OAuth discovery when adding a remote MCP server via its UI.
This module implements just enough OAuth to satisfy that flow for a personal
single-user deployment:

  1. /.well-known/oauth-authorization-server  — metadata discovery
  2. /register                                 — dynamic client registration
  3. /authorize                                — auto-approve, redirect with code
  4. /token                                    — exchange code for token

No actual auth is enforced at the OAuth level. The MCP endpoint itself is
protected by the optional MCP_API_KEY environment variable if set.
"""

from __future__ import annotations

import os
import secrets
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

# CORS headers required so Claude.ai's browser can reach our endpoints
_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, MCP-Protocol-Version",
}


def _base_url() -> str:
    """Derive the server's public base URL.

    Checks (in order):
      RAILWAY_PUBLIC_DOMAIN  — set automatically by Railway
      SERVER_URL             — manual override
    Falls back to localhost for local dev.
    """
    domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip()
    if domain:
        return f"https://{domain}"
    return os.environ.get("SERVER_URL", "http://localhost:8080").rstrip("/")


# In-memory code store — fine for a single-process personal server
_pending_codes: dict[str, bool] = {}


async def handle_preflight(request: Request) -> Response:
    """Handle CORS preflight OPTIONS requests."""
    return Response(status_code=204, headers=_CORS_HEADERS)


async def handle_metadata(request: Request) -> JSONResponse:
    """RFC 8414 OAuth Authorization Server Metadata."""
    base = _base_url()
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
        headers={**_CORS_HEADERS, "Cache-Control": "public, max-age=3600"},
    )


async def handle_register(request: Request) -> JSONResponse:
    """Dynamic client registration (RFC 7591) — accepts any client."""
    # Note: if client_secret is omitted, client_secret_expires_at is not required.
    # Setting token_endpoint_auth_method to "none" means no secret is needed.
    return JSONResponse(
        {
            "client_id": "claude-mcp-client",
            "client_id_issued_at": 0,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "redirect_uris": [],
        },
        status_code=201,
        headers=_CORS_HEADERS,
    )


async def handle_authorize(request: Request) -> Response:
    """Authorization endpoint — auto-approves and immediately redirects with a code."""
    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", "")

    if not redirect_uri:
        return Response("Missing redirect_uri", status_code=400, headers=_CORS_HEADERS)

    code = secrets.token_urlsafe(32)
    _pending_codes[code] = True

    params: dict[str, str] = {"code": code}
    if state:
        params["state"] = state

    return RedirectResponse(
        url=f"{redirect_uri}?{urlencode(params)}",
        status_code=302,
        headers=_CORS_HEADERS,
    )


async def handle_token(request: Request) -> JSONResponse:
    """Token endpoint — accepts any code and returns a long-lived bearer token.

    The token value is not validated by the MCP server since no MCP_API_KEY
    is required. Access control is at the network layer (Railway URL obscurity)
    or via MCP_API_KEY if configured.
    """
    return JSONResponse(
        {
            "access_token": secrets.token_urlsafe(32),
            "token_type": "Bearer",
            "expires_in": 86400 * 365,  # 1 year
        },
        headers=_CORS_HEADERS,
    )


OAUTH_ROUTES: list[Route] = [
    Route(
        "/.well-known/oauth-authorization-server",
        handle_metadata,
        methods=["GET", "OPTIONS"],
    ),
    Route("/register", handle_register, methods=["POST", "OPTIONS"]),
    Route("/authorize", handle_authorize, methods=["GET", "OPTIONS"]),
    Route("/token", handle_token, methods=["POST", "OPTIONS"]),
]
