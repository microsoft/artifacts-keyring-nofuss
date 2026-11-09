"""Exercise token retries through the CLI, without mocking the retry helper."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest import mock

import pytest
import requests

from artifacts_keyring_nofuss import _cli, _http

if TYPE_CHECKING:
    from pathlib import Path


def _response(payload: object, status: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(payload).encode()
    _ = response.content
    return response


@pytest.fixture(autouse=True)
def token_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURE_FEDERATED_TOKEN_FILE", raising=False)
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/oidc")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-secret")
    monkeypatch.setenv("ARTIFACTS_KEYRING_NOFUSS_RETRIES", "3")


@pytest.mark.parametrize("stage", ["oidc", "entra"])
@pytest.mark.parametrize(
    "failure",
    [
        "connection",
        "timeout",
        "429",
        "500",
        "502",
        "503",
        "504",
        "json",
        "missing",
        "empty",
        "blank",
        "non-string",
        "non-object",
    ],
)
def test_recovers_with_one_shared_retry_budget(
    stage: str, failure: str, capsys: pytest.CaptureFixture[str]
) -> None:
    field = "value" if stage == "oidc" else "access_token"
    if failure == "connection":
        failed: requests.Response | Exception = requests.ConnectionError("down")
    elif failure == "timeout":
        failed = requests.Timeout("slow")
    elif failure.isdigit():
        failed = _response({field: "must-not-use"}, int(failure))
    elif failure == "json":
        failed = _response(None)
        failed._content = b"not-json"
    else:
        payloads: dict[str, object] = {
            "missing": {},
            "empty": {field: ""},
            "blank": {field: " \t\n"},
            "non-string": {field: 123},
            "non-object": [],
        }
        failed = _response(payloads[failure])
    oidc = _response({"value": "assertion"})
    bearer = _response({"access_token": "TOKEN"})
    responses = (
        [failed, failed, oidc, bearer]
        if stage == "oidc"
        else [oidc, failed, failed, bearer]
    )
    with (
        mock.patch(
            "artifacts_keyring_nofuss._http.requests.request", side_effect=responses
        ) as req,
        mock.patch(
            "artifacts_keyring_nofuss._http.random.uniform",
            side_effect=lambda low, high: high,
        ),
        mock.patch("artifacts_keyring_nofuss._http.time.sleep") as sleep,
    ):
        assert _cli.main(["mint-token"]) == 0
    assert req.call_count == 4
    assert sleep.call_args_list == [mock.call(0.5), mock.call(1.0)]
    output = capsys.readouterr()
    assert output.out == "TOKEN\n"
    assert output.err == ""


@pytest.mark.parametrize("stage", ["oidc", "entra"])
@pytest.mark.parametrize("status", [200, 400, 401, 403, 503])
@pytest.mark.parametrize("command", ["stdout", "file", "exec"])
def test_exhaustion_fails_closed(
    stage: str,
    status: int,
    command: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    field = "value" if stage == "oidc" else "access_token"
    # Even a plausible token in an error response must never be accepted.
    failed = _response({field: "" if status == 200 else "must-not-use"}, status)
    attempts = 3 if status in {200, 503} else 1
    responses = [failed] * attempts
    if stage == "entra":
        responses.insert(0, _response({"value": "assertion"}))
    output_file = tmp_path / "token"
    output_file.write_text("existing")
    args = {
        "stdout": ["mint-token"],
        "file": ["mint-token", "--output-file", str(output_file)],
        "exec": ["exec", "--", "must-not-run"],
    }[command]
    with (
        mock.patch(
            "artifacts_keyring_nofuss._http.requests.request", side_effect=responses
        ) as req,
        mock.patch("artifacts_keyring_nofuss._http.time.sleep") as sleep,
        mock.patch("artifacts_keyring_nofuss._cli.subprocess.run") as run,
    ):
        assert _cli.main(args) == 1
    assert req.call_count == attempts + (stage == "entra")
    assert sleep.call_count == attempts - 1
    run.assert_not_called()
    assert output_file.read_text() == "existing"
    output = capsys.readouterr()
    assert output.out == ""
    assert "error:" in output.err
    assert "must-not-use" not in output.err
    assert "request-secret" not in output.err


def test_retry_budget_override_disables_token_response_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARTIFACTS_KEYRING_NOFUSS_RETRIES", "1")
    with (
        mock.patch(
            "artifacts_keyring_nofuss._http.requests.request",
            return_value=_response({"value": ""}),
        ) as req,
        mock.patch("artifacts_keyring_nofuss._http.time.sleep") as sleep,
    ):
        assert _cli.main(["mint-token"]) == 1
    req.assert_called_once()
    sleep.assert_not_called()


def test_backoff_ceiling_is_exponential_and_capped() -> None:
    with mock.patch(
        "artifacts_keyring_nofuss._http.random.uniform", return_value=0.25
    ) as uniform:
        assert [_http._backoff_delay(i) for i in range(1, 10)] == [0.25] * 9
    assert uniform.call_args_list == [
        mock.call(0, ceiling)
        for ceiling in (0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0, 8.0, 8.0)
    ]
