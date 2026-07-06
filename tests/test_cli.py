"""Tests for the ``mint-token`` / ``exec`` CLI and ``mint_bearer``."""

from __future__ import annotations

import runpy
import sys
from typing import TYPE_CHECKING
from unittest import mock

import pytest
import requests

from artifacts_keyring_nofuss import _cli, _workload_identity

if TYPE_CHECKING:
    from pathlib import Path


def _set_env(monkeypatch: pytest.MonkeyPatch, fed: Path) -> None:
    fed.write_text("assertion")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-123")
    monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", str(fed))
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-abc")


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_TENANT_ID"):
        monkeypatch.delenv(var, raising=False)


class TestMintToken:
    def test_prints_token_to_stdout(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        _set_env(monkeypatch, tmp_path / "fed")
        with mock.patch(
            "artifacts_keyring_nofuss._cli.mint_bearer", return_value="TOKEN"
        ) as minted:
            rc = _cli.main(["mint-token"])
        assert rc == 0
        out = capsys.readouterr()
        assert out.out == "TOKEN\n"
        assert out.err == ""
        minted.assert_called_once()

    @pytest.mark.usefixtures("clean_env")
    def test_missing_tenant_returns_1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        fed = tmp_path / "fed"
        fed.write_text("assertion")
        monkeypatch.setenv("AZURE_CLIENT_ID", "client-123")
        monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", str(fed))
        rc = _cli.main(["mint-token"])
        assert rc == 1
        out = capsys.readouterr()
        assert out.out == ""
        assert "tenant" in out.err.lower()

    def test_exchange_returns_none_returns_1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        _set_env(monkeypatch, tmp_path / "fed")
        with mock.patch("artifacts_keyring_nofuss._cli.mint_bearer", return_value=None):
            rc = _cli.main(["mint-token"])
        assert rc == 1
        out = capsys.readouterr()
        assert out.out == ""
        assert "mint" in out.err.lower()

    def test_output_file_writes_token(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        _set_env(monkeypatch, tmp_path / "fed")
        out_file = tmp_path / "token.txt"
        with mock.patch(
            "artifacts_keyring_nofuss._cli.mint_bearer", return_value="TOKEN"
        ):
            rc = _cli.main(["mint-token", "--output-file", str(out_file)])
        assert rc == 0
        assert capsys.readouterr().out == ""
        assert out_file.read_text() == "TOKEN"
        assert (out_file.stat().st_mode & 0o777) == 0o600

    def test_python_m_invocation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        _set_env(monkeypatch, tmp_path / "fed")
        monkeypatch.setattr(sys, "argv", ["prog", "mint-token"])
        with (
            mock.patch(
                "artifacts_keyring_nofuss._cli.mint_bearer", return_value="TOKEN"
            ),
            pytest.raises(SystemExit) as exc,
        ):
            runpy.run_module("artifacts_keyring_nofuss", run_name="__main__")
        assert exc.value.code == 0
        assert capsys.readouterr().out == "TOKEN\n"


class TestExec:
    def test_sets_token_env_and_forwards_exit_code(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _set_env(monkeypatch, tmp_path / "fed")
        captured: dict[str, str] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> mock.MagicMock:
            env = kwargs["env"]
            assert isinstance(env, dict)
            captured["token"] = env.get("ARTIFACTS_KEYRING_NOFUSS_TOKEN", "")
            captured["cmd"] = " ".join(cmd)
            result = mock.MagicMock()
            result.returncode = 42
            return result

        with (
            mock.patch(
                "artifacts_keyring_nofuss._cli.mint_bearer", return_value="TOKEN"
            ),
            mock.patch(
                "artifacts_keyring_nofuss._cli.subprocess.run", side_effect=fake_run
            ),
        ):
            rc = _cli.main(["exec", "--", "echo", "hi"])

        assert rc == 42
        assert captured["token"] == "TOKEN"
        assert captured["cmd"] == "echo hi"

    def test_mint_failure_returns_1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        _set_env(monkeypatch, tmp_path / "fed")
        with (
            mock.patch("artifacts_keyring_nofuss._cli.mint_bearer", return_value=None),
            mock.patch("artifacts_keyring_nofuss._cli.subprocess.run") as run,
        ):
            rc = _cli.main(["exec", "--", "echo", "hi"])
        assert rc == 1
        run.assert_not_called()
        assert capsys.readouterr().err != ""


class TestMintBearer:
    def test_returns_token_on_200(self) -> None:
        resp = mock.MagicMock()
        resp.json.return_value = {"access_token": "TOKEN"}
        with mock.patch(
            "artifacts_keyring_nofuss._workload_identity._http.request",
            return_value=resp,
        ) as req:
            token = _workload_identity.mint_bearer("cid", "assertion", "tid")
        assert token == "TOKEN"
        req.assert_called_once()

    def test_returns_none_on_failure(self) -> None:
        with mock.patch(
            "artifacts_keyring_nofuss._workload_identity._http.request",
            side_effect=requests.ConnectionError("boom"),
        ):
            token = _workload_identity.mint_bearer("cid", "assertion", "tid")
        assert token is None
