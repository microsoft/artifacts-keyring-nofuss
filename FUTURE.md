# Future: Switching to Entra Tokens with Narrow Scopes

This document captures research done in March 2026 on replacing Azure DevOps
session tokens with direct Entra ID bearer tokens. The goal was to use
narrow, packaging-only scopes instead of the broad `user_impersonation` scope.

**TL;DR** — Narrow scopes don't work today with the first-party Azure Artifacts
client ID. When they do, switch to the `entra-tokens` branch as a starting
point.

## Background

Azure DevOps is moving from session tokens (the `_apis/Token/SessionTokens`
endpoint) toward direct Entra ID bearer tokens. The official
`artifacts-credprovider` already supports returning Entra tokens directly
(opt-in via `ARTIFACTS_CREDENTIALPROVIDER_RETURN_ENTRA_TOKENS=true`).

We implemented a full MSAL-based replacement (branch: `entra-tokens`) that
removes the session token exchange entirely. It works, but the resulting
token has **full `user_impersonation` scope** — not limited to packaging.

## What We Learned

### The official credprovider also uses `.default` scope

Across **all** branches of `microsoft/artifacts-credprovider` (master,
releases/2.0.0, releases/2.0.1, and `users/embetten/update-scopes`), the MSAL
scope is always:

```csharp
// MsalConstants.cs
public const string AzureDevOpsResource = "499b84ac-1321-427f-aa17-267ca6975798/.default";
```

The client ID is always:

```csharp
// AzureArtifacts.cs
public const string ClientId = "d5a56ea4-7369-46b8-a538-c370805301bf";
```

No branch uses narrow scopes like `vso.packaging` in the MSAL token request.

### Narrow scopes like `vso.packaging` only apply to session token exchange

The `vso.packaging` / `vso.packaging_write` scopes appear **only** in
`VstsSessionTokenClient.cs` — the session token exchange step that happens
*after* obtaining the broad Entra token:

```csharp
// VstsSessionTokenClient.cs (releases/2.0.0)
private const string TokenScope = "vso.packaging_write vso.drop_write";

// VstsSessionTokenClient.cs (users/embetten/update-scopes)
private const string TokenScope = "vso.packaging_write";
```

This is how scope narrowing works today: broad Entra token → exchange for a
session token with limited `vso.*` scope.

### Narrow Entra scopes fail with the first-party client ID

We tried requesting `499b84ac-1321-427f-aa17-267ca6975798/vso.packaging`
directly with client ID `d5a56ea4-...`:

```
AADSTS65002: Consent between first party application
'd5a56ea4-7369-46b8-a538-c370805301bf' and first party resource
'499b84ac-1321-427f-aa17-267ca6975798' must be configured via
preauthorization — applications owned and operated by Microsoft must get
approval from the API owner.
```

This means the Azure Artifacts app has not been pre-authorized for narrow
`vso.*` scopes — only `.default` works.

### Narrow scopes DO work with custom app registrations

Azure DevOps documentation confirms that scopes like
`499b84ac-1321-427f-aa17-267ca6975798/vso.packaging` work when you register
**your own** Entra application and configure API permissions. This doesn't help
for a general-purpose keyring package that can't require users to set up their
own app registration.

### Token scope verified by testing

We wrote `test_scope.py` (on the `entra-tokens` branch) which probes various
ADO API endpoints with the MSAL `.default` token. Results:

| Endpoint                           | Status |
|------------------------------------|--------|
| Packaging feeds                    | ✅ 200 |
| Projects list                      | ✅ 200 |
| Git repositories                   | ✅ 200 |
| Work items (by IDs)                | ✅ 200 |
| User profile                       | ✅ 200 |
| PAT token management               | ✅ 200 |

The token grants **full access** to anything the user has permissions on —
confirming it is NOT restricted to packaging operations.

## What to Do When Narrow Scopes Become Available

When Microsoft pre-authorizes narrow scopes on the Azure Artifacts client ID
(or provides a new client ID specifically for packaging), the migration path is:

1. **Start from the `entra-tokens` branch** — it has a working MSAL
   implementation with `SilentProvider` (cache + refresh), `ManagedIdentityProvider`,
   and `BrowserProvider` (interactive PKCE).

2. **Change the scope** in `_constants.py`:
   ```python
   # Change from:
   SCOPE = f"{RESOURCE_ID}/.default"
   # To (example):
   SCOPE = f"{RESOURCE_ID}/vso.packaging"
   ```

3. **If a new client ID is provided**, update `CLIENT_ID` in `_constants.py`.

4. **Remove the session token exchange** — it won't be needed if the Entra
   token itself is packaging-scoped.

5. **Run `test_scope.py`** to verify the token is actually limited — the
   non-packaging endpoints (projects, git, work items, PATs) should return
   401/403.

6. **Delete `_session_token.py`**, `_azure_cli.py`, `_browser.py` — the MSAL
   module replaces all of them.

7. **Update `pyproject.toml`** — add `msal>=1.20` to dependencies, since the
   session-token version only needs `keyring` + `requests`.

## Using Narrow Scopes with a Custom App Registration

Narrow scopes like `vso.packaging` **do work** — but only with your own Entra
app registration, not the first-party Azure Artifacts client ID. A
[Stack Overflow answer](https://stackoverflow.com/questions/78336900/azure-devops-python-correct-scopes-for-getting-a-token)
confirms this with a working example:

1. **Register an app** in Entra ID (Azure Portal → App registrations)
2. **Add API permission**: Azure DevOps → Delegated → the `vso.*` scopes you
   need (e.g. `vso.packaging` for read-only packaging, `vso.code` for code)
3. **Add redirect URI**: Under "Mobile and Desktop applications", add
   `http://localhost` and enable public client flows
4. **Use the fully qualified scope** in MSAL:
   ```python
   SCOPE = ["499b84ac-1321-427f-aa17-267ca6975798/vso.packaging"]
   ```
5. The resulting token's `scp` claim will show only the granted permissions
   (e.g. `vso.packaging`) instead of `user_impersonation`

The key insight: the first-party client ID `d5a56ea4-...` cannot request narrow
scopes (fails with AADSTS65002), but a custom app registration can — after
configuring the appropriate API permissions in Entra.

For this package, using a custom app registration would mean either:
- Requiring users to register their own app and pass a client ID (via env var)
- Registering a shared app (with admin consent in each tenant)

The `test_narrow_scopes.py` script in the repo root can be used to verify:
```bash
AZURE_CLIENT_ID=<your-app-id> python test_narrow_scopes.py
```

## Key Files on `entra-tokens` Branch

- `src/artifacts_keyring_nofuss/_msal_auth.py` — MSAL flows (silent, browser)
- `src/artifacts_keyring_nofuss/_constants.py` — scope + client ID
- `src/artifacts_keyring_nofuss/_backend.py` — provider chain without session tokens
- `test_scope.py` — scope verification script
- `README.md` — includes SSH/remote port forwarding docs

## References

- [Azure DevOps custom scopes](https://devblogs.microsoft.com/devops/azure-devops-now-supports-custom-azure-active-directory-entra-scopes/)
- [SO: Correct scopes for getting a token](https://stackoverflow.com/questions/78336900/azure-devops-python-correct-scopes-for-getting-a-token) — confirms narrow scopes work with custom app registrations
- [MSAL Python docs](https://msal-python.readthedocs.io/)
- [artifacts-credprovider source](https://github.com/microsoft/artifacts-credprovider)
- [artifacts-keyring v2 branch](https://github.com/microsoft/artifacts-keyring/tree/users/embetten/prepare-2.0.0)
