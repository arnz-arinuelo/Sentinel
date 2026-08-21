"""Azure Workload Identity Federation client-auth for the Entra ID provider.

Replaces ``client_secret`` with a `client_assertion` built from the AKS-issued
ServiceAccount token (``AZURE_FEDERATED_TOKEN_FILE``), per RFC 7523 / Entra's
federated identity credential mechanism. See ``src/auth/providers.py``.
"""

from urllib.parse import parse_qs

from src.auth.providers import (
    _AZURE_CLIENT_ASSERTION_TYPE,
    _entra_workload_identity_auth,
    _read_azure_federated_token,
)


class _FakeClient:
    def __init__(self, client_id):
        self.client_id = client_id


def test_read_azure_federated_token_reads_current_file_contents(tmp_path, monkeypatch):
    token_file = tmp_path / "azure-identity-token"
    token_file.write_text("first-token\n", encoding="utf-8")
    monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", str(token_file))

    assert _read_azure_federated_token() == "first-token"

    # AKS rotates the file's contents periodically — confirm we don't cache.
    token_file.write_text("rotated-token\n", encoding="utf-8")
    assert _read_azure_federated_token() == "rotated-token"


def test_entra_workload_identity_auth_builds_client_assertion_body(tmp_path, monkeypatch):
    token_file = tmp_path / "azure-identity-token"
    token_file.write_text("federated-jwt-value", encoding="utf-8")
    monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", str(token_file))

    client = _FakeClient(client_id="entra-app-client-id")
    uri, headers, body = _entra_workload_identity_auth(
        client, "POST", "https://login.microsoftonline.com/tenant/oauth2/v2.0/token", {}, ""
    )

    params = parse_qs(body)
    assert params["client_id"] == ["entra-app-client-id"]
    assert params["client_assertion_type"] == [_AZURE_CLIENT_ASSERTION_TYPE]
    assert params["client_assertion"] == ["federated-jwt-value"]
    # A client_secret must never be sent alongside a client_assertion.
    assert "client_secret" not in params
    assert uri == "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
