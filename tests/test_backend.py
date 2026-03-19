"""Tests for artifacts-keyring-nofuss."""

from __future__ import annotations

import base64
import json
import time
from unittest import mock

import pytest

from artifacts_keyring_nofuss._backend import (
    _account_from_token,
    _discover,
    _is_supported,
    _validate_auth_uri,
    _validate_vsts_authority,
    ArtifactsKeyringBackend,
)


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
        result = _discover("https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/")
        assert result == ("my-tenant", "https://app.vssps.visualstudio.com")

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_untrusted_auth_uri_rejected(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response(
            www_auth="Bearer authorization_uri=https://evil.com/my-tenant",
            vsts_authority="https://app.vssps.visualstudio.com",
        )
        result = _discover("https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/")
        assert result is None

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_untrusted_authority_rejected(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response(
            www_auth="Bearer authorization_uri=https://login.microsoftonline.com/my-tenant",
            vsts_authority="https://evil.com",
        )
        result = _discover("https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/")
        assert result is None

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_http_authority_rejected(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response(
            www_auth="Bearer authorization_uri=https://login.microsoftonline.com/my-tenant",
            vsts_authority="http://app.vssps.visualstudio.com",
        )
        result = _discover("https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/")
        assert result is None

    @mock.patch("artifacts_keyring_nofuss._backend.requests.get")
    def test_missing_headers(self, mock_get: mock.MagicMock) -> None:
        mock_get.return_value = self._mock_response()
        result = _discover("https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/")
        assert result is None


# ---------------------------------------------------------------------------
# _account_from_token
# ---------------------------------------------------------------------------


class TestAccountFromToken:
    def _make_jwt(self, claims: dict) -> str:
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        return f"{header}.{payload}.signature"

    def test_extracts_upn(self) -> None:
        token = self._make_jwt({"upn": "user@example.com"})
        assert _account_from_token(token) == "user@example.com"

    def test_extracts_unique_name(self) -> None:
        token = self._make_jwt({"unique_name": "user@example.com"})
        assert _account_from_token(token) == "user@example.com"

    def test_extracts_oid(self) -> None:
        token = self._make_jwt({"oid": "abc-123"})
        assert _account_from_token(token) == "abc-123"

    def test_returns_none_for_garbage(self) -> None:
        assert _account_from_token("not-a-jwt") is None


# ---------------------------------------------------------------------------
# Cache TTL
# ---------------------------------------------------------------------------


class TestCacheTTL:
    @mock.patch("artifacts_keyring_nofuss._backend._discover")
    @mock.patch("artifacts_keyring_nofuss._backend._provider.run_chain")
    @mock.patch("artifacts_keyring_nofuss._backend._session_token.exchange")
    def test_cache_expires(
        self,
        mock_exchange: mock.MagicMock,
        mock_chain: mock.MagicMock,
        mock_discover: mock.MagicMock,
    ) -> None:
        mock_discover.return_value = ("tenant", "https://app.vssps.visualstudio.com")
        mock_chain.return_value = "bearer-token"
        mock_exchange.return_value = "session-token"

        backend = ArtifactsKeyringBackend()
        url = "https://pkgs.dev.azure.com/org/proj/_packaging/feed/pypi/simple/"

        # First call populates cache
        cred1 = backend.get_credential(url, None)
        assert cred1 is not None
        assert mock_exchange.call_count == 1

        # Second call uses cache (no new exchange)
        cred2 = backend.get_credential(url, None)
        assert cred2 is cred1
        assert mock_exchange.call_count == 1

        # Simulate expired cache by backdating the timestamp
        entry = backend._cache[url]
        backend._cache[url] = (entry[0], time.monotonic() - 3600)

        # Third call should re-authenticate
        mock_exchange.return_value = "new-session-token"
        cred3 = backend.get_credential(url, None)
        assert cred3 is not None
        assert cred3.password == "new-session-token"
        assert mock_exchange.call_count == 2
