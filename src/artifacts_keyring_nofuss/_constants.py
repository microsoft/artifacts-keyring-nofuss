"""Constants shared across auth flows."""

# Azure DevOps resource ID (for az cli --resource flag)
RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798"

# Netlocs that indicate an Azure DevOps Artifacts feed
SUPPORTED_NETLOCS = frozenset(
    {
        "pkgs.dev.azure.com",
        "pkgs.visualstudio.com",
        "pkgs.codedev.ms",
        "pkgs.vsts.me",
    }
)

# Allowed Azure AD authorization hosts (for tenant discovery)
ALLOWED_AUTH_HOSTS = frozenset(
    {
        "login.microsoftonline.com",
        "login.windows.net",
        "login.microsoft.com",
    }
)

# Allowed Azure DevOps authority hosts (where bearer tokens may be sent)
ALLOWED_VSTS_AUTHORITY_HOSTS = frozenset(
    {
        "app.vssps.visualstudio.com",
        "app.vssps.dev.azure.com",
        "app.vssps.codedev.ms",
        "app.vssps.vsts.me",
    }
)
