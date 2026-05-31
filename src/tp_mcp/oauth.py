"""OAuth 2.0 server for Claude.ai custom connector registration.

Uses the MCP SDK's built-in auth infrastructure so all RFC compliance
(PKCE, redirect_uri matching, token expiry, etc.) is handled correctly.

The provider is a simple in-memory implementation — suitable for a single-user
personal deployment. No actual authorization UI is shown; every request is
auto-approved.
"""

from __future__ import annotations

import os
import secrets
import time
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.routes import create_auth_routes, create_protected_resource_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.routing import Route


def get_issuer_url() -> str:
    """Return the server's public base URL.

    Railway sets RAILWAY_PUBLIC_DOMAIN automatically. You can also set
    SERVER_URL manually (must include scheme, e.g. https://...).
    """
    domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip()
    if domain:
        return f"https://{domain}"
    return os.environ.get("SERVER_URL", "http://localhost:8080").rstrip("/")


class SimpleAuthProvider(OAuthAuthorizationServerProvider):
    """In-memory OAuth provider — auto-approves every authorization request."""

    def __init__(self) -> None:
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    # ------------------------------------------------------------------
    # Authorization code flow
    # ------------------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Auto-approve: immediately generate a code and redirect back."""
        code = secrets.token_urlsafe(32)
        self._auth_codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or [],
            expires_at=time.time() + 300,  # 5 minutes
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
        )
        return construct_redirect_uri(
            str(params.redirect_uri),
            code=code,
            state=params.state,
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self._auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._auth_codes.pop(authorization_code.code, None)
        token = secrets.token_urlsafe(32)
        self._access_tokens[token] = AccessToken(
            token=token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 86400 * 365,
        )
        return OAuthToken(
            access_token=token,
            token_type="Bearer",
            expires_in=86400 * 365,
        )

    # ------------------------------------------------------------------
    # Token validation
    # ------------------------------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        return self._access_tokens.get(token)

    # ------------------------------------------------------------------
    # Refresh tokens (not used — return None / no-op)
    # ------------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:  # pragma: no cover
        raise NotImplementedError("Refresh tokens are not supported")

    async def revoke_token(self, token: Any) -> None:
        if hasattr(token, "token"):
            self._access_tokens.pop(token.token, None)


def build_oauth_routes(issuer_url: str) -> list[Route]:
    """Create MCP SDK OAuth + Protected Resource Metadata routes."""
    provider = SimpleAuthProvider()

    auth_routes = create_auth_routes(
        provider=provider,
        issuer_url=AnyHttpUrl(issuer_url),
        client_registration_options=ClientRegistrationOptions(enabled=True),
        revocation_options=RevocationOptions(enabled=False),
    )

    # RFC 9728: /.well-known/oauth-protected-resource/mcp
    # Claude.ai fetches this to discover which auth server protects /mcp.
    resource_routes = create_protected_resource_routes(
        resource_url=AnyHttpUrl(f"{issuer_url}/mcp"),
        authorization_servers=[AnyHttpUrl(issuer_url)],
    )

    return auth_routes + resource_routes
