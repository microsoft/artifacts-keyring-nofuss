"""Command-line interface for minting Azure DevOps feed bearer tokens.

Provides a hang-proof, pure-Python alternative to
``az account get-access-token`` for CI runners.  It reuses the Workload
Identity Federation exchange (federated OIDC assertion -> Azure AD bearer)
so a token can be minted on the runner and injected into an isolated
Docker build as a BuildKit secret.

Subcommands:
- ``mint-token``: print (or write) a freshly minted bearer token.
- ``exec``: mint a token, expose it via ``ARTIFACTS_KEYRING_NOFUSS_TOKEN``,
  and run a wrapped command.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from . import _constants as C
from ._workload_identity import mint_bearer

_TOKEN_ENV_VAR = "ARTIFACTS_KEYRING_NOFUSS_TOKEN"  # noqa: S105


def _resolve_token(tenant: str | None, resource: str) -> str | None:
    """Mint a bearer token from the ambient OIDC env, or print an error.

    Returns the token on success, or ``None`` after writing a concise error
    to stderr.  Never prints the token to stderr.
    """
    tenant_id = (tenant or os.environ.get("AZURE_TENANT_ID", "")).strip()
    if not tenant_id:
        print(
            "error: no tenant specified (pass --tenant or set AZURE_TENANT_ID)",
            file=sys.stderr,
        )
        return None

    client_id = os.environ.get("AZURE_CLIENT_ID", "").strip()
    token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE", "").strip()
    if not client_id or not token_file:
        print(
            "error: AZURE_CLIENT_ID and AZURE_FEDERATED_TOKEN_FILE must be set "
            "(run azure/login@v2 first)",
            file=sys.stderr,
        )
        return None

    try:
        assertion = Path(token_file).read_text().strip()
    except OSError:
        print(
            f"error: cannot read federated token file {token_file}",
            file=sys.stderr,
        )
        return None

    if not assertion:
        print(
            f"error: federated token file {token_file} is empty",
            file=sys.stderr,
        )
        return None

    token = mint_bearer(client_id, assertion, tenant_id, resource=resource)
    if not token:
        print("error: failed to mint bearer token", file=sys.stderr)
        return None

    return token


def _cmd_mint_token(args: argparse.Namespace) -> int:
    token = _resolve_token(args.tenant, args.resource)
    if token is None:
        return 1

    output_file = args.output_file
    if output_file:
        path = Path(output_file)
        path.write_text(token)
        path.chmod(0o600)
    else:
        sys.stdout.write(token)
        sys.stdout.write("\n")

    return 0


def _cmd_exec(args: argparse.Namespace) -> int:
    command = args.command
    if not command:
        print("error: no command given after '--'", file=sys.stderr)
        return 1

    token = _resolve_token(args.tenant, args.resource)
    if token is None:
        return 1

    env = os.environ.copy()
    env[_TOKEN_ENV_VAR] = token

    completed = subprocess.run(command, env=env, check=False)
    return completed.returncode


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="artifacts-keyring-nofuss",
        description="Mint Azure DevOps feed bearer tokens without the Azure CLI.",
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    mint = subparsers.add_parser(
        "mint-token",
        help="Mint a bearer token and print it (or write it to a file).",
    )
    mint.add_argument(
        "--tenant",
        default=None,
        help="Azure AD tenant ID (defaults to AZURE_TENANT_ID).",
    )
    mint.add_argument(
        "--resource",
        default=C.RESOURCE_ID,
        help="Resource ID to scope the token to (defaults to Azure DevOps).",
    )
    mint.add_argument(
        "--output-file",
        default=None,
        help="Write the token to this path (0600) instead of stdout.",
    )

    exec_parser = subparsers.add_parser(
        "exec",
        help="Mint a token, export it, and run a wrapped command.",
    )
    exec_parser.add_argument(
        "--tenant",
        default=None,
        help="Azure AD tenant ID (defaults to AZURE_TENANT_ID).",
    )
    exec_parser.add_argument(
        "--resource",
        default=C.RESOURCE_ID,
        help="Resource ID to scope the token to (defaults to Azure DevOps).",
    )
    exec_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to run after '--', with the token in the environment.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # For `exec`, argparse.REMAINDER captures a leading '--' verbatim; strip it.
    if getattr(args, "command", None) and args.command[0] == "--":
        args.command = args.command[1:]

    if args.command_name == "mint-token":
        return _cmd_mint_token(args)
    return _cmd_exec(args)
