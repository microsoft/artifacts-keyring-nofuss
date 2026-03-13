"""Constants shared across auth flows."""

# Azure Artifacts public client application ID (from artifacts-credprovider)
CLIENT_ID = "d5a56ea4-7369-46b8-a538-c370805301bf"

# Azure DevOps resource scope
SCOPE = "499b84ac-1321-427f-aa17-267ca6975798/.default"

# Azure DevOps resource ID (for az cli --resource flag, without /.default)
RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798"

# Redirect URI for public client auth code flow on Linux
REDIRECT_URI = "http://localhost"

# Netlocs that indicate an Azure DevOps Artifacts feed
SUPPORTED_NETLOCS = frozenset({
    "pkgs.dev.azure.com",
    "pkgs.visualstudio.com",
    "pkgs.codedev.ms",
    "pkgs.vsts.me",
})
