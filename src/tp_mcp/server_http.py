"""HTTP transport for TrainingPeaks MCP Server (Railway deployment).

Exposes the MCP server over Streamable HTTP on /mcp.

Environment variables:
  TP_AUTH_COOKIE          TrainingPeaks Production_tpAuth cookie (required)
  MCP_API_KEY             Optional bearer token to protect /mcp
  RAILWAY_PUBLIC_DOMAIN   Set automatically by Railway; used for OAuth issuer URL
  SERVER_URL              Manual override for the public base URL
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import AsyncIterator
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from tp_mcp.server import server, _validate_auth_on_startup
from tp_mcp.oauth import build_oauth_routes, get_issuer_url

logger = logging.getLogger("tp-mcp.http")


# ---------------------------------------------------------------------------
# Debug logging middleware
# ---------------------------------------------------------------------------

class DebugLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        body = b""
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
        logger.info(
            ">>> %s %s | body: %s",
            request.method,
            request.url.path,
            body[:300].decode(errors="replace") if body else "",
        )
        response = await call_next(request)
        logger.info("<<< %s %s → %s", request.method, request.url.path, response.status_code)
        return response


# ---------------------------------------------------------------------------
# Optional API-key middleware
# ---------------------------------------------------------------------------

class APIKeyMiddleware(BaseHTTPMiddleware):
    _PUBLIC_PATHS = {
        "/",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource/mcp",
        "/register",
        "/authorize",
        "/token",
    }

    def __init__(self, app: Any, api_key: str) -> None:
        super().__init__(app)
        self._api_key = api_key

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self._PUBLIC_PATHS:
            return await call_next(request)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[len("Bearer "):] != self._api_key:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return await call_next(request)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Any:
    """Create and return the ASGI application."""

    issuer_url = get_issuer_url()
    logger.info("OAuth issuer URL: %s", issuer_url)
    oauth_routes = build_oauth_routes(issuer_url)

    session_manager = StreamableHTTPSessionManager(
        app=server,
        stateless=False,
        session_idle_timeout=1800,
    )

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        logger.info("TrainingPeaks MCP HTTP server starting")
        await _validate_auth_on_startup()
        async with session_manager.run():
            yield
        logger.info("TrainingPeaks MCP HTTP server stopped")

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok", "server": "trainingpeaks-mcp"})

    # Starlette handles health + OAuth routes only.
    # /mcp is NOT mounted here — Starlette's Mount("/mcp") redirects
    # exact-path POST /mcp to /mcp/ with 307, which breaks MCP clients.
    starlette_app = Starlette(
        lifespan=lifespan,
        routes=[Route("/", health), *oauth_routes],
    )

    async def dispatch(scope, receive, send) -> None:
        """Route /mcp straight to the session manager; all else to Starlette."""
        if scope["type"] == "http" and scope.get("path", "").rstrip("/") == "/mcp":
            await session_manager.handle_request(scope, receive, send)
        else:
            await starlette_app(scope, receive, send)

    # Build middleware stack (innermost first)
    app: Any = CORSMiddleware(
        dispatch,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api_key = os.environ.get("MCP_API_KEY", "").strip()
    if api_key:
        logger.info("API key authentication enabled")
        app = APIKeyMiddleware(app, api_key)
    else:
        logger.warning("MCP_API_KEY is not set — /mcp is unauthenticated")

    app = DebugLoggingMiddleware(app)
    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_http_server(host: str = "0.0.0.0", port: int = 8080) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    try:
        uvicorn.run(create_app(), host=host, port=port)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        logger.exception("HTTP server error")
        return 1
