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
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
                "none",
            ],
        },
        headers={"Cache-Control": "public, max-age=3600"},
    )


async def handle_register(request: Request) -> JSONResponse:
    """Dynamic client registration — accepts any client, returns fixed credentials."""
    return JSONResponse(
        {
            "client_id": "claude-mcp-client",
            "client_secret": "not-validated",
            "client_id_issued_at": 0,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
        status_code=201,
    )


async def handle_authorize(request: Request) -> Response:
    """Authorization endpoint — auto-approves and immediately redirects with a code."""
    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", "")

    if not redirect_uri:
        return Response("Missing redirect_uri", status_code=400)

    code = secrets.token_urlsafe(32)
    _pending_codes[code] = True

    params: dict[str, str] = {"code": code}
    if state:
        params["state"] = state

    return RedirectResponse(
        url=f"{redirect_uri}?{urlencode(params)}",
        status_code=302,
    )


async def handle_token(request: Request) -> JSONResponse:
    """Token endpoint — accepts any code and returns a long-lived bearer token.

    The token value is irrelevant since the MCP server does not validate it
    (access control is at the network/API-key layer, not here).
    """
    return JSONResponse(
        {
            "access_token": "tp-mcp-bearer-token",
            "token_type": "Bearer",
            "expires_in": 86400 * 365,  # 1 year — effectively permanent
        }
    )


OAUTH_ROUTES: list[Route] = [
    Route("/.well-known/oauth-authorization-server", handle_metadata, methods=["GET"]),
    Route("/register", handle_register, methods=["POST"]),
    Route("/authorize", handle_authorize, methods=["GET"]),
    Route("/token", handle_token, methods=["POST"]),
]
