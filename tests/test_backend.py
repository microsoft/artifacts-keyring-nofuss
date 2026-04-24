"""Tests for artifacts-keyring-nofuss."""

from __future__ import annotations

import base64
import json
from unittest import mock

import pytest
import requests

from artifacts_keyring_nofuss._backend import (
    ArtifactsKeyringBackend,
    _account_from_token,
    _discover,
    _ensure_scheme,
    _hostname_matches,
    _is_service_principal_token,
    _is_supported,
    _strip_userinfo,
    _validate_auth_uri,
    _validate_vsts_authority,
)
from artifacts_keyring_nofuss._env_var import ENV_VAR, FALLBACK_ENV_VAR, EnvVarProvider
from artifacts_keyring_nofuss._workload_identity import WorkloadIdentityProvider


def _make_jwt(claims: dict[str, str]) -> str:
    """Build a fake JWT with the given payload claims."""
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    )
    return f"{header}.{payload}.signature"


# Pre-built tokens for tests that need JWT claim detection
USER_JWT = _make_jwt({"upn": "user@example.com", "idtyp": "user", "oid": "u-123"})
SP_JWT = _make_jwt({"oid": "sp-123", "idtyp": "app", "appid": "client-id"})

# ---------------------------------------------------------------------------
# _ensure_scheme
# ---------------------------------------------------------------------------


class TestEnsureScheme:
    def test_adds_https(self) -> None:
        assert (
            _ensure_scheme("pkgs.dev.azure.com/org") == "https://pkgs.dev.azure.com/org"
        )

    def test_preserves_https(self) -> None:
        url = "https://pkgs.dev.azure.com/org"
        assert _ensure_scheme(url) == url

    def test_preserves_http(self) -> None:
        url = "http://pkgs.dev.azure.com/org"
        assert _ensure_scheme(url) == url


# ---------------------------------------------------------------------------
# _strip_userinfo
# ---------------------------------------------------------------------------


class TestStripUserinfo:
    def test_strips_token_username(self) -> None:
        result = _strip_userinfo(
            "https://__token__@pkgs.dev.azure.com/org/_packaging/feed/pypi/simple/"
        )
        assert result == "https://pkgs.dev.azure.com/org/_packaging/feed/pypi/simple/"

    def test_strips_user_and_password(self) -> None:
        result = _strip_userinfo("https://user:pass@pkgs.dev.azure.com/org/")
        assert result == "https://pkgs.dev.azure.com/org/"

    def test_no_userinfo_unchanged(self) -> None:
        url = "https://pkgs.dev.azure.com/org/"
        assert _strip_userinfo(url) == url

    def test_handles_bare_hostname(self) -> None:
        result = _strip_userinfo(
            "__token__@myorg.pkgs.visualstudio.com/_packaging/feed/pypi/simple/"
        )
        assert (
            result == "https://myorg.pkgs.visualstudio.com/_packaging/feed/pypi/simple/"
        )


# ---------------------------------------------------------------------------
# _hostname_matches
# ---------------------------------------------------------------------------


class TestHostnameMatches:
    @pytest.mark.parametrize(
        "hostname",
        [
            "pkgs.dev.azure.com",
            "pkgs.visualstudio.com",
            "pkgs.codedev.ms",
            "pkgs.vsts.me",
        ],
    )
    def test_exact_matches(self, hostname: str) -> None:
        assert _hostname_matches(hostname) is True

    @pytest.mark.parametrize(
        "hostname",
        [
            "myorg.pkgs.visualstudio.com",
            "myorg.pkgs.dev.azure.com",
            "sub.pkgs.codedev.ms",
            "deep.sub.pkgs.vsts.me",
        ],
    )
    def test_subdomain_matches(self, hostname: str) -> None:
        assert _hostname_matches(hostname) is True

    @pytest.mark.parametrize(
        "hostname",
        [
            "evil-pkgs.dev.azure.com",
            "evil.com",
            "pkgs.dev.azure.com.evil.com",
            "notpkgs.visualstudio.com",
            "",
        ],
    )
    def test_rejects_spoofed_domains(self, hostname: str) -> None:
        assert _hostname_matches(hostname) is False


# ---------------------------------------------------------------------------
# _is_supported
# ---------------------------------------------------------------------------


class TestIsSupported:
    @pytest.mark.parametrize(
        "url",
        [
            "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/",
            "https://pkgs.visualstudio.com/org/_packaging/feed/pypi/simple/",
            "https://pkgs.codedev.ms/org/_packaging/feed/pypi/simple/",
            "https://pkgs.vsts.me/org/_packaging/feed/pypi/simple/",
            # Subdomain-prefixed feed hostnames
            "https://myorg.pkgs.visualstudio.com/_packaging/feed/pypi/simple/",
            "https://myorg.pkgs.dev.azure.com/proj/_packaging/feed/pypi/simple/",
            # With userinfo
            "https://__token__@myorg.pkgs.visualstudio.com/_packaging/feed/pypi/simple/",
            # Without scheme (bare hostname from uv)
            "pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/",
            "myorg.pkgs.visualstudio.com/_packaging/feed/pypi/simple/",
        ],
    )
    def test_supported_urls(self, url: str) -> None:
        assert _is_supported(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://pypi.org/simple/",
            "https://evil.com/pkgs.dev.azure.com/",
            "https://pkgs.dev.azure.com.evil.com/",
            "https://evil-pkgs.dev.azure.com/",
            "",
            "not-a-url",
        ],
    )
    def test_unsupported_urls(self, url: str) -> None:
        assert _is_supported(url) is False


# ---------------------------------------------------------------------------
# _validate_auth_uri
# ---------------------------------------------------------------------------


class TestValidateAuthUri:
    @pytest.mark.parametrize(
        "uri",
        [
            "https://login.microsoftonline.com/tenant-id",
            "https://login.windows.net/tenant-id",
            "https://login.microsoft.com/tenant-id",
        ],
    )
    def test_trusted_uris(self, uri: str) -> None:
        assert _validate_auth_uri(uri) is True

    @pytest.mark.parametrize(
        "uri",
        [
            "https://evil.com/tenant-id",
            "https://login.microsoftonline.com.evil.com/tenant-id",
            "https://attacker.example.com",
            "",
            # Scheme/port/userinfo edge cases
            "http://login.microsoftonline.com/tenant-id",  # HTTP rejected
            "https://login.microsoftonline.com:8443/tenant-id",  # non-default port
            "https://user:pass@login.microsoftonline.com/tenant-id",  # userinfo
        ],
    )
    def test_untrusted_uris(self, uri: str) -> None:
        assert _validate_auth_uri(uri) is False


# ---------------------------------------------------------------------------
# _validate_vsts_authority
# ---------------------------------------------------------------------------


class TestValidateVstsAuthority:
    @pytest.mark.parametrize(
        "url",
        [
            "https://app.vssps.visualstudio.com",
            "https://app.vssps.dev.azure.com",
            "https://app.vssps.codedev.ms",
            "https://app.vssps.vsts.me",
            "https://vssps.visualstudio.com",
            "https://vssps.dev.azure.com",
            "https://vssps.codedev.ms",
            "https://vssps.vsts.me",
            "https://app.vssps.visualstudio.com/",  # trailing slash OK
            "https://vssps.dev.azure.com/my-org",  # org-name path OK
            "https://vssps.dev.azure.com/my-org/",  # trailing slash OK
        ],
    )
    def test_trusted_authorities(self, url: str) -> None:
        assert _validate_vsts_authority(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.com",
            "https://app.vssps.visualstudio.com.evil.com",
            "http://app.vssps.visualstudio.com",  # HTTP not allowed
            "https://attacker.example.com",
            "",
            # Port/path/userinfo edge cases
            "https://app.vssps.visualstudio.com:444",  # non-default port
            "https://vssps.dev.azure.com/org/deep/path",  # multi-segment path
            "https://user:pass@app.vssps.visualstudio.com",  # userinfo
        ],
    )
    def test_untrusted_authorities(self, url: str) -> None:
        assert _validate_vsts_authority(url) is False


# ---------------------------------------------------------------------------
# _discover
# ---------------------------------------------------------------------------


class TestDiscover:
    def _mock_response(
        self,
        www_auth: str = "",
        vsts_authority: str = "",
    ) -> mock.MagicMock:
        resp = mock.MagicMock()
        resp.headers = {
            "WWW-Authenticate": www_auth,
            "X-VSS-AuthorizationEndpoint": vsts_authority,
        }
        return resp

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_valid_discovery(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response(
            www_auth="Bearer authorization_uri=https://login.microsoftonline.com/my-tenant",
            vsts_authority="https://app.vssps.visualstudio.com",
        )
        result = _discover(
            "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        )
        assert result == ("my-tenant", "https://app.vssps.visualstudio.com")

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_untrusted_auth_uri_rejected(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response(
            www_auth="Bearer authorization_uri=https://evil.com/my-tenant",
            vsts_authority="https://app.vssps.visualstudio.com",
        )
        result = _discover(
            "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        )
        assert result is None

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_untrusted_authority_rejected(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response(
            www_auth="Bearer authorization_uri=https://login.microsoftonline.com/my-tenant",
            vsts_authority="https://evil.com",
        )
        result = _discover(
            "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        )
        assert result is None

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_http_authority_rejected(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response(
            www_auth="Bearer authorization_uri=https://login.microsoftonline.com/my-tenant",
            vsts_authority="http://app.vssps.visualstudio.com",
        )
        result = _discover(
            "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        )
        assert result is None

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_missing_headers(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response()
        result = _discover(
            "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        )
        assert result is None


# ---------------------------------------------------------------------------
# _account_from_token
# ---------------------------------------------------------------------------


class TestAccountFromToken:
    def test_extracts_upn(self) -> None:
        token = _make_jwt({"upn": "user@example.com"})
        assert _account_from_token(token) == "user@example.com"

    def test_extracts_unique_name(self) -> None:
        token = _make_jwt({"unique_name": "user@example.com"})
        assert _account_from_token(token) == "user@example.com"

    def test_extracts_oid(self) -> None:
        token = _make_jwt({"oid": "abc-123"})
        assert _account_from_token(token) == "abc-123"

    def test_returns_none_for_garbage(self) -> None:
        assert _account_from_token("not-a-jwt") is None


# ---------------------------------------------------------------------------
# Cache TTL
# ---------------------------------------------------------------------------


class TestCacheTTL:
    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    @mock.patch("artifacts_keyring_nofuss._backend._provider.run_chain")
    def test_cache_expires(
        self,
        mock_chain: mock.MagicMock,
        mock_discover: mock.MagicMock,
        mock_exchange: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_chain.return_value = USER_JWT
        mock_exchange.return_value = "session-token"

        backend = ArtifactsKeyringBackend()
        url = "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"

        now = 1000.0
        with mock.patch(
            "artifacts_keyring_nofuss._backend.time.monotonic", side_effect=lambda: now
        ):
            # First call populates cache
            cred1 = backend.get_credential(url, None)
            assert cred1 is not None
            assert mock_chain.call_count == 1
            assert mock_exchange.call_count == 1

            # Second call uses cache (no new chain run and no new exchange)
            cred2 = backend.get_credential(url, None)
            assert cred2 is cred1
            assert mock_chain.call_count == 1
            assert mock_exchange.call_count == 1

            # Advance time past TTL (50 min = 3000s)
            now = 4100.0
            mock_chain.return_value = USER_JWT
            mock_exchange.return_value = "new-session-token"
            cred3 = backend.get_credential(url, None)
            assert cred3 is not None
            assert cred3.password == "new-session-token"
            assert mock_chain.call_count == 2
            assert mock_exchange.call_count == 2


# ---------------------------------------------------------------------------
# Session token (default behaviour)
# ---------------------------------------------------------------------------


class TestSessionTokenDefault:
    """By default, get_credential exchanges the bearer for a VssSessionToken."""

    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    @mock.patch("artifacts_keyring_nofuss._backend._provider.run_chain")
    def test_returns_session_token(
        self,
        mock_chain: mock.MagicMock,
        mock_discover: mock.MagicMock,
        mock_exchange: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_chain.return_value = USER_JWT
        mock_exchange.return_value = "my-session-token"

        backend = ArtifactsKeyringBackend()
        url = "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        cred = backend.get_credential(url, None)

        assert cred is not None
        assert cred.username == "VssSessionToken"
        assert cred.password == "my-session-token"
        mock_exchange.assert_called_once_with(
            USER_JWT, "https://app.vssps.visualstudio.com"
        )

    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    @mock.patch("artifacts_keyring_nofuss._backend._provider.run_chain")
    def test_get_password_returns_session_token(
        self,
        mock_chain: mock.MagicMock,
        mock_discover: mock.MagicMock,
        mock_exchange: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_chain.return_value = USER_JWT
        mock_exchange.return_value = "my-session-token"

        backend = ArtifactsKeyringBackend()
        url = "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        password = backend.get_password(url, None)

        assert password == "my-session-token"

    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    @mock.patch("artifacts_keyring_nofuss._backend._provider.run_chain")
    def test_subdomain_feed_url_works(
        self,
        mock_chain: mock.MagicMock,
        mock_discover: mock.MagicMock,
        mock_exchange: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_chain.return_value = USER_JWT
        mock_exchange.return_value = "session-token-123"

        backend = ArtifactsKeyringBackend()
        url = (
            "https://__token__@myorg.pkgs.visualstudio.com/_packaging/feed/pypi/simple/"
        )
        cred = backend.get_credential(url, None)

        assert cred is not None
        assert cred.password == "session-token-123"

    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    @mock.patch("artifacts_keyring_nofuss._backend._provider.run_chain")
    def test_returns_none_when_exchange_fails(
        self,
        mock_chain: mock.MagicMock,
        mock_discover: mock.MagicMock,
        mock_exchange: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_chain.return_value = USER_JWT
        mock_exchange.return_value = None

        backend = ArtifactsKeyringBackend()
        url = "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        cred = backend.get_credential(url, None)

        assert cred is None


# ---------------------------------------------------------------------------
# Discovery with userinfo
# ---------------------------------------------------------------------------


class TestDiscoverWithUserinfo:
    """Ensure discovery strips userinfo before making the GET request."""

    def _mock_response(
        self,
        www_auth: str = "",
        vsts_authority: str = "",
    ) -> mock.MagicMock:
        resp = mock.MagicMock()
        resp.headers = {
            "WWW-Authenticate": www_auth,
            "X-VSS-AuthorizationEndpoint": vsts_authority,
        }
        return resp

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_strips_userinfo_before_request(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response(
            www_auth="Bearer authorization_uri=https://login.microsoftonline.com/my-tenant",
            vsts_authority="https://app.vssps.visualstudio.com",
        )
        _discover(
            "https://__token__@pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        )
        # The GET request should NOT contain __token__
        called_url = mock_get.call_args[0][0]
        assert "__token__" not in called_url
        assert "pkgs.dev.azure.com" in called_url


# ---------------------------------------------------------------------------
# Service principal tokens (MI/SP/WIF) — bearer returned directly
# ---------------------------------------------------------------------------


class TestServicePrincipalTokens:
    """SP tokens skip session exchange and return the Entra bearer directly."""

    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    @mock.patch("artifacts_keyring_nofuss._backend._provider.run_chain")
    def test_sp_token_skips_session_exchange(
        self,
        mock_chain: mock.MagicMock,
        mock_discover: mock.MagicMock,
        mock_exchange: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_chain.return_value = SP_JWT

        backend = ArtifactsKeyringBackend()
        url = "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        cred = backend.get_credential(url, None)

        assert cred is not None
        assert cred.username == "bearer"
        assert cred.password == SP_JWT
        # Session exchange should NOT be called for SP tokens
        mock_exchange.assert_not_called()

    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    @mock.patch("artifacts_keyring_nofuss._backend._provider.run_chain")
    def test_user_token_does_session_exchange(
        self,
        mock_chain: mock.MagicMock,
        mock_discover: mock.MagicMock,
        mock_exchange: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_chain.return_value = USER_JWT
        mock_exchange.return_value = "session-token"

        backend = ArtifactsKeyringBackend()
        url = "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        cred = backend.get_credential(url, None)

        assert cred is not None
        assert cred.username == "VssSessionToken"
        assert cred.password == "session-token"
        mock_exchange.assert_called_once_with(
            USER_JWT, "https://app.vssps.visualstudio.com"
        )

    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    @mock.patch("artifacts_keyring_nofuss._backend._provider.run_chain")
    def test_sp_token_get_password(
        self,
        mock_chain: mock.MagicMock,
        mock_discover: mock.MagicMock,
        mock_exchange: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_chain.return_value = SP_JWT

        backend = ArtifactsKeyringBackend()
        url = "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"
        password = backend.get_password(url, None)

        assert password == SP_JWT
        mock_exchange.assert_not_called()


# ---------------------------------------------------------------------------
# _is_service_principal_token
# ---------------------------------------------------------------------------


class TestIsServicePrincipalToken:
    def test_app_idtyp_is_sp(self) -> None:
        token = _make_jwt({"idtyp": "app", "oid": "sp-123"})
        assert _is_service_principal_token(token) is True

    def test_user_idtyp_is_not_sp(self) -> None:
        token = _make_jwt({"idtyp": "user", "upn": "user@example.com"})
        assert _is_service_principal_token(token) is False

    def test_scp_claim_means_delegated(self) -> None:
        token = _make_jwt({"oid": "u-123", "scp": "user_impersonation"})
        assert _is_service_principal_token(token) is False

    def test_roles_claim_means_app_only(self) -> None:
        token = _make_jwt({"oid": "sp-123", "roles": "Packaging.Read"})
        assert _is_service_principal_token(token) is True

    def test_no_idtyp_with_upn_is_user(self) -> None:
        token = _make_jwt({"upn": "user@example.com", "oid": "u-123"})
        assert _is_service_principal_token(token) is False

    def test_no_idtyp_with_preferred_username_is_user(self) -> None:
        token = _make_jwt({"preferred_username": "user@example.com", "oid": "u-123"})
        assert _is_service_principal_token(token) is False

    def test_unknown_claims_default_to_user(self) -> None:
        token = _make_jwt({"oid": "mystery-123"})
        assert _is_service_principal_token(token) is False

    def test_garbage_token_defaults_to_user(self) -> None:
        assert _is_service_principal_token("not-a-jwt") is False


# ---------------------------------------------------------------------------
# EnvVarProvider
# ---------------------------------------------------------------------------


class TestEnvVarProvider:
    def test_returns_token_when_set(self) -> None:
        provider = EnvVarProvider()
        with mock.patch.dict("os.environ", {ENV_VAR: "my-bearer-token"}):
            assert provider.get_token("any-tenant") == "my-bearer-token"

    def test_returns_none_when_unset(self) -> None:
        provider = EnvVarProvider()
        with mock.patch.dict("os.environ", {}, clear=True):
            assert provider.get_token("any-tenant") is None

    def test_returns_none_when_empty(self) -> None:
        provider = EnvVarProvider()
        with mock.patch.dict("os.environ", {ENV_VAR: ""}):
            assert provider.get_token("any-tenant") is None

    def test_strips_whitespace(self) -> None:
        provider = EnvVarProvider()
        with mock.patch.dict("os.environ", {ENV_VAR: "  my-token  \n"}):
            assert provider.get_token("any-tenant") == "my-token"

    def test_fallback_to_vss_nuget_accesstoken(self) -> None:
        provider = EnvVarProvider()
        with mock.patch.dict(
            "os.environ", {FALLBACK_ENV_VAR: "fallback-token"}, clear=True
        ):
            assert provider.get_token("any-tenant") == "fallback-token"

    def test_primary_takes_precedence_over_fallback(self) -> None:
        provider = EnvVarProvider()
        with mock.patch.dict(
            "os.environ",
            {ENV_VAR: "primary-token", FALLBACK_ENV_VAR: "fallback-token"},
        ):
            assert provider.get_token("any-tenant") == "primary-token"


class TestEnvVarProviderIntegration:
    """End-to-end: env var token flows through to a session token."""

    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    def test_env_var_token_used_for_exchange(
        self,
        mock_discover: mock.MagicMock,
        mock_exchange: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_exchange.return_value = "my-session-token"

        backend = ArtifactsKeyringBackend()
        url = "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"

        with mock.patch.dict("os.environ", {ENV_VAR: "env-bearer-token"}):
            cred = backend.get_credential(url, None)

        assert cred is not None
        assert cred.username == "VssSessionToken"
        assert cred.password == "my-session-token"
        mock_exchange.assert_called_once_with(
            "env-bearer-token", "https://app.vssps.visualstudio.com"
        )


# ---------------------------------------------------------------------------
# WorkloadIdentityProvider
# ---------------------------------------------------------------------------


class TestWorkloadIdentityProvider:
    def test_returns_none_when_env_vars_missing(self) -> None:
        provider = WorkloadIdentityProvider()
        with mock.patch.dict("os.environ", {}, clear=True):
            assert provider.get_token("any-tenant") is None

    def test_returns_none_when_client_id_missing(self) -> None:
        provider = WorkloadIdentityProvider()
        with mock.patch.dict(
            "os.environ",
            {
                "AZURE_FEDERATED_TOKEN_FILE": "/mock/federated/token",
                "AZURE_TENANT_ID": "t",
            },
            clear=True,
        ):
            assert provider.get_token("any-tenant") is None

    def test_returns_none_when_token_file_missing(self) -> None:
        provider = WorkloadIdentityProvider()
        with mock.patch.dict(
            "os.environ",
            {"AZURE_CLIENT_ID": "cid", "AZURE_TENANT_ID": "t"},
            clear=True,
        ):
            assert provider.get_token("any-tenant") is None

    def test_returns_none_when_token_file_unreadable(self) -> None:
        provider = WorkloadIdentityProvider()
        with mock.patch.dict(
            "os.environ",
            {
                "AZURE_CLIENT_ID": "cid",
                "AZURE_FEDERATED_TOKEN_FILE": "/nonexistent/path",
            },
            clear=True,
        ):
            assert provider.get_token("any-tenant") is None

    @mock.patch("artifacts_keyring_nofuss._workload_identity.requests.post")
    def test_exchanges_federated_token(self, mock_post: mock.MagicMock) -> None:
        mock_post.return_value.json.return_value = {"access_token": "bearer-123"}
        mock_post.return_value.raise_for_status = mock.MagicMock()

        provider = WorkloadIdentityProvider()
        with (
            mock.patch.dict(
                "os.environ",
                {
                    "AZURE_CLIENT_ID": "my-client-id",
                    "AZURE_FEDERATED_TOKEN_FILE": "/mock/federated/token",
                    "AZURE_TENANT_ID": "my-tenant",
                },
                clear=True,
            ),
            mock.patch("pathlib.Path.read_text", return_value="federated-jwt\n"),
        ):
            result = provider.get_token("discovered-tenant")

        assert result == "bearer-123"
        # Should use AZURE_TENANT_ID over discovered tenant
        call_args = mock_post.call_args
        assert "my-tenant" in call_args[0][0]
        assert call_args[1]["data"]["client_id"] == "my-client-id"
        assert call_args[1]["data"]["client_assertion"] == "federated-jwt"

    @mock.patch("artifacts_keyring_nofuss._workload_identity.requests.post")
    def test_falls_back_to_discovered_tenant(self, mock_post: mock.MagicMock) -> None:
        mock_post.return_value.json.return_value = {"access_token": "bearer-456"}
        mock_post.return_value.raise_for_status = mock.MagicMock()

        provider = WorkloadIdentityProvider()
        with (
            mock.patch.dict(
                "os.environ",
                {
                    "AZURE_CLIENT_ID": "cid",
                    "AZURE_FEDERATED_TOKEN_FILE": "/mock/federated/token",
                },
                clear=True,
            ),
            mock.patch("pathlib.Path.read_text", return_value="federated-jwt"),
        ):
            result = provider.get_token("discovered-tenant")

        assert result == "bearer-456"
        assert "discovered-tenant" in mock_post.call_args[0][0]

    @mock.patch("artifacts_keyring_nofuss._workload_identity.requests.post")
    def test_returns_none_on_http_error(self, mock_post: mock.MagicMock) -> None:
        mock_post.return_value.raise_for_status.side_effect = requests.HTTPError("401")

        provider = WorkloadIdentityProvider()
        with (
            mock.patch.dict(
                "os.environ",
                {
                    "AZURE_CLIENT_ID": "cid",
                    "AZURE_FEDERATED_TOKEN_FILE": "/mock/federated/token",
                },
                clear=True,
            ),
            mock.patch("pathlib.Path.read_text", return_value="federated-jwt"),
        ):
            assert provider.get_token("tenant") is None
