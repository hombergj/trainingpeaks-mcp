"""HTTP transport for TrainingPeaks MCP Server (Railway deployment).

Exposes the MCP server over Streamable HTTP on a single /mcp endpoint.

Security:
- Set MCP_API_KEY env var to require Bearer token on every request.
  If unset the endpoint is unauthenticated (not recommended for public deploys).
- Set TP_AUTH_COOKIE env var with the Production_tpAuth cookie value.
  This replaces the keyring/file credential store used in local setups.
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import AsyncIterator

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

# Import the shared server object (tools, handlers, etc. are already registered)
from tp_mcp.server import server, _validate_auth_on_startup
from tp_mcp.oauth import build_oauth_routes, get_issuer_url

logger = logging.getLogger("tp-mcp.http")


# ---------------------------------------------------------------------------
# Optional API-key middleware
# ---------------------------------------------------------------------------

class APIKeyMiddleware(BaseHTTPMiddleware):
    """Reject requests that don't carry the expected Bearer token.

    Only active when MCP_API_KEY is set in the environment.
    Health-check requests to / always pass through.
    """

    def __init__(self, app, api_key: str) -> None:
        super().__init__(app)
        self._api_key = api_key

    # Paths that must be reachable without auth (OAuth discovery + health)
    _PUBLIC_PATHS = {
        "/",
        "/.well-known/oauth-authorization-server",
        "/register",
        "/authorize",
        "/token",
    }

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self._PUBLIC_PATHS:
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[len("Bearer "):] != self._api_key:
            return JSONResponse(
                {"error": "Unauthorized", "message": "Valid Bearer token required"},
                status_code=401,
            )
        return await call_next(request)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Starlette:
    """Create and return the Starlette ASGI application."""

    issuer_url = get_issuer_url()
    logger.info("OAuth issuer URL: %s", issuer_url)
    oauth_routes = build_oauth_routes(issuer_url)

    session_manager = StreamableHTTPSessionManager(
        app=server,
        stateless=False,
        session_idle_timeout=1800,  # 30 min idle session cleanup
    )

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        logger.info("TrainingPeaks MCP HTTP server starting")
        await _validate_auth_on_startup()
        async with session_manager.run():
            yield
        logger.info("TrainingPeaks MCP HTTP server stopped")

    async def handle_mcp(scope, receive, send) -> None:
        await session_manager.handle_request(scope, receive, send)

    async def health(request: Request) -> Response:
        return JSONResponse({"status": "ok", "server": "trainingpeaks-mcp"})

    app = Starlette(
        lifespan=lifespan,
        routes=[
            Route("/", health),
            Mount("/mcp", app=handle_mcp),
            *oauth_routes,
        ],
    )

    # CORS — required for Claude.ai browser to reach OAuth endpoints
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # Wrap with API-key middleware if configured
    api_key = os.environ.get("MCP_API_KEY", "").strip()
    if api_key:
        logger.info("API key authentication enabled")
        app = APIKeyMiddleware(app, api_key)  # type: ignore[assignment]
    else:
        logger.warning(
            "MCP_API_KEY is not set — the /mcp endpoint is unauthenticated. "
            "Set MCP_API_KEY to protect your deployment."
        )

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_http_server(host: str = "0.0.0.0", port: int = 8080) -> int:
    """Start the HTTP server with uvicorn."""
    import logging as _logging

    _logging.basicConfig(
        level=_logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    app = create_app()

    try:
        uvicorn.run(app, host=host, port=port)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        logger.exception("HTTP server error")
        return 1
