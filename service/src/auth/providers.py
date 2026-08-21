import os

from authlib.common.urls import add_params_to_qs
from authlib.integrations.starlette_client import OAuth

from src.config import settings

oauth = OAuth()

# RFC 7523 client-assertion type used by Azure AD/Entra ID's token endpoint
# when authenticating with a federated identity credential instead of a
# client_secret.
_AZURE_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _read_azure_federated_token() -> str:
    """Read the AKS-injected ServiceAccount token used for Azure Workload
    Identity Federation. Read fresh (not cached) on every call since AKS
    rotates the file's contents periodically."""
    token_file = os.environ["AZURE_FEDERATED_TOKEN_FILE"]
    with open(token_file, encoding="utf-8") as f:
        return f.read().strip()


def _entra_workload_identity_auth(client, method, uri, headers, body):
    """Authlib token-endpoint-auth-method: authenticates to Entra ID's token
    endpoint using Azure Workload Identity Federation instead of a
    client_secret. Presents the AKS-issued ServiceAccount token as a
    `client_assertion`; Entra validates it against the app registration's
    Federated Identity Credential (issuer + subject), so no shared secret is
    ever held by this service. Mirrors `encode_client_secret_post` in
    authlib.oauth2.auth, but swaps client_secret for client_assertion.
    """
    body = add_params_to_qs(
        body or "",
        [
            ("client_id", client.client_id),
            ("client_assertion_type", _AZURE_CLIENT_ASSERTION_TYPE),
            ("client_assertion", _read_azure_federated_token()),
        ],
    )
    if "Content-Length" in headers:
        headers["Content-Length"] = str(len(body))
    return uri, headers, body


# Use Workload Identity Federation only when no client secret is configured
# and AKS has actually injected the federated token file (via the
# sentinel-service ServiceAccount annotation + pod label — see the Helm
# chart). Falls back to the classic client_secret flow otherwise, so this
# stays safe for local dev / non-AKS environments.
_use_entra_workload_identity = bool(
    settings.entra_client_id
    and settings.entra_tenant_id
    and not settings.entra_client_secret
    and os.environ.get("AZURE_FEDERATED_TOKEN_FILE")
)

# Google (OAuth2 + OpenID Connect)
if settings.google_client_id:
    oauth.register(
        name="google",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
        code_challenge_method="S256",
    )

# GitHub (OAuth2 — not full OIDC, uses userinfo endpoint)
# Note: GitHub does not support PKCE as of 2025
if settings.github_client_id:
    oauth.register(
        name="github",
        client_id=settings.github_client_id,
        client_secret=settings.github_client_secret,
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "user:email"},
    )

# Microsoft EntraID (OAuth2 + OIDC)
if settings.entra_client_id and settings.entra_tenant_id:
    _entra_kwargs = dict(
        name="entra_id",
        client_id=settings.entra_client_id,
        client_secret=settings.entra_client_secret,
        server_metadata_url=(
            f"https://login.microsoftonline.com/{settings.entra_tenant_id}"
            "/v2.0/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid email profile"},
        code_challenge_method="S256",
    )
    if _use_entra_workload_identity:
        _entra_kwargs["token_endpoint_auth_method"] = _entra_workload_identity_auth
    oauth.register(**_entra_kwargs)

# Dex (self-hosted OIDC) — config-gated; inert unless DEX_CLIENT_ID +
# DEX_SERVER_METADATA_URL are set. Used by the Layer-2 isolation prover for faithful
# token issuance against an ephemeral target. Mirrors the OIDC providers above.
if settings.dex_client_id and settings.dex_server_metadata_url:
    oauth.register(
        name="dex",
        client_id=settings.dex_client_id,
        client_secret=settings.dex_client_secret,
        server_metadata_url=settings.dex_server_metadata_url,
        client_kwargs={"scope": "openid email profile"},
        code_challenge_method="S256",
    )


def get_configured_providers() -> list[str]:
    providers = []
    if settings.google_client_id:
        providers.append("google")
    if settings.github_client_id:
        providers.append("github")
    if settings.entra_client_id and settings.entra_tenant_id:
        providers.append("entra_id")
    if settings.dex_client_id and settings.dex_server_metadata_url:
        providers.append("dex")
    return providers
