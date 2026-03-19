# Copilot Instructions

## Build & Lint

```bash
pip install -e ".[dev]"        # editable install with dev tools
pre-commit install             # one-time git hook setup
pre-commit run --all-files     # run all hooks manually
ruff check src/                # lint only
ruff format src/               # format only
mypy src/                      # type-check (strict mode)
```

Versioning is dynamic via `setuptools-scm` from git tags.

## Architecture

This is a [keyring](https://pypi.org/project/keyring/) backend plugin (~435 lines) that authenticates pip/twine against Azure DevOps Artifacts feeds using pure Python — no .NET, no MSAL.

**Authentication flow** (`_backend.py` → `_provider.py` → `_session_token.py`):

1. Validate the service URL against `SUPPORTED_NETLOCS` in `_constants.py`
2. **Discover** the Azure AD tenant by making an unauthenticated GET to the feed URL and parsing the `WWW-Authenticate` header
3. **Get a bearer token** by running the provider chain (Azure CLI → Managed Identity)
4. **Exchange** the bearer token for a scoped Azure DevOps session token (`vso.packaging`, read-only)
5. Cache and return the session token as Basic auth credentials

**Provider chain** (`_provider.py`):
- Providers implement the `TokenProvider` Protocol (structural subtyping — no base class inheritance)
- `run_chain()` tries each provider in order, catches all exceptions, and returns the first successful token
- Default chain: `["azure_cli", "managed_identity"]` — overridable via `ARTIFACTS_KEYRING_NOFUSS_PROVIDER` env var or `keyringrc.cfg`
- New providers: add the implementation in a `_<name>.py` module, then register it in the `PROVIDERS` dict and `DEFAULT_CHAIN` list in `_backend.py`

**Keyring integration**:
- `ArtifactsKeyringBackend` extends `keyring.backend.KeyringBackend` with priority 9.9
- Registered via the `[project.entry-points."keyring.backends"]` in `pyproject.toml`
- Read-only: `set_password()` and `delete_password()` raise `NotImplementedError`

## Key Conventions

- **Graceful degradation**: provider failures are caught, logged, and the chain continues to the next provider. Never raise from a provider.
- **Debug logging**: controlled by `ARTIFACTS_KEYRING_NOFUSS_DEBUG=1` env var. Log to stderr via the package-level logger in `__init__.py`.
- **All modules except `__init__.py` are prefixed with `_`** (private).
