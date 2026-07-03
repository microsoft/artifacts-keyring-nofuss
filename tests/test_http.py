"""Tests for the HTTP retry helper (``_http``)."""

from __future__ import annotations

from unittest import mock

import pytest
import requests

from artifacts_keyring_nofuss import _http


def _response(status_code: int = 200) -> mock.MagicMock:
    resp = mock.MagicMock(spec=requests.Response)
    resp.status_code = status_code
    return resp


@mock.patch("artifacts_keyring_nofuss._http.time.sleep")
@mock.patch("artifacts_keyring_nofuss._http.requests.request")
class TestRequestRetries:
    def test_returns_immediately_on_success(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        mock_request.return_value = _response(200)
        resp = _http.request("GET", "https://example.com")
        assert resp.status_code == 200
        assert mock_request.call_count == 1
        mock_sleep.assert_not_called()

    def test_retries_on_connection_error_then_succeeds(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        mock_request.side_effect = [
            requests.ConnectionError("boom"),
            _response(200),
        ]
        resp = _http.request("GET", "https://example.com", max_attempts=3)
        assert resp.status_code == 200
        assert mock_request.call_count == 2
        assert mock_sleep.call_count == 1

    def test_retries_on_timeout_then_succeeds(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        mock_request.side_effect = [requests.Timeout("slow"), _response(200)]
        resp = _http.request("POST", "https://example.com", max_attempts=3)
        assert resp.status_code == 200
        assert mock_request.call_count == 2

    def test_raises_last_exception_when_all_attempts_fail(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        mock_request.side_effect = requests.ConnectionError("down")
        with pytest.raises(requests.ConnectionError):
            _http.request("GET", "https://example.com", max_attempts=3)
        assert mock_request.call_count == 3
        # Slept between attempts but not after the final failure.
        assert mock_sleep.call_count == 2

    def test_does_not_retry_non_transient_exception(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        mock_request.side_effect = requests.exceptions.InvalidURL("bad url")
        with pytest.raises(requests.exceptions.InvalidURL):
            _http.request("GET", "not-a-url", max_attempts=3)
        assert mock_request.call_count == 1
        mock_sleep.assert_not_called()

    def test_does_not_retry_ssl_error(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        mock_request.side_effect = requests.exceptions.SSLError("cert invalid")
        with pytest.raises(requests.exceptions.SSLError):
            _http.request("GET", "https://example.com", max_attempts=3)
        assert mock_request.call_count == 1
        mock_sleep.assert_not_called()

    def test_max_attempts_is_capped(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        mock_request.side_effect = requests.ConnectionError("down")
        with pytest.raises(requests.ConnectionError):
            _http.request("GET", "https://example.com", max_attempts=999)
        assert mock_request.call_count == _http._MAX_ATTEMPTS

    def test_retries_on_retryable_status_then_succeeds(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        mock_request.side_effect = [_response(503), _response(200)]
        resp = _http.request("GET", "https://example.com", max_attempts=3)
        assert resp.status_code == 200
        assert mock_request.call_count == 2

    def test_returns_retryable_status_after_exhausting_attempts(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        mock_request.return_value = _response(503)
        resp = _http.request("GET", "https://example.com", max_attempts=2)
        assert resp.status_code == 503
        assert mock_request.call_count == 2

    def test_does_not_retry_non_retryable_status(
        self, mock_request: mock.MagicMock, mock_sleep: mock.MagicMock
    ) -> None:
        # 401 carries WWW-Authenticate for discovery / signals a rejected bearer
        # for exchange — the caller must inspect it, so we do not retry.
        mock_request.return_value = _response(401)
        resp = _http.request("GET", "https://example.com", max_attempts=3)
        assert resp.status_code == 401
        assert mock_request.call_count == 1
        mock_sleep.assert_not_called()


class TestConfiguredAttempts:
    def test_default_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_http._MAX_ATTEMPTS_ENV, raising=False)
        assert _http._configured_attempts() == _http.DEFAULT_MAX_ATTEMPTS

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_http._MAX_ATTEMPTS_ENV, "5")
        assert _http._configured_attempts() == 5

    def test_invalid_env_falls_back_to_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_http._MAX_ATTEMPTS_ENV, "not-a-number")
        assert _http._configured_attempts() == _http.DEFAULT_MAX_ATTEMPTS

    def test_env_override_is_clamped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_http._MAX_ATTEMPTS_ENV, "0")
        assert _http._configured_attempts() == _http._MIN_ATTEMPTS
        monkeypatch.setenv(_http._MAX_ATTEMPTS_ENV, "999")
        assert _http._configured_attempts() == _http._MAX_ATTEMPTS
