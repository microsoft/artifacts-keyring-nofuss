"""Constants shared across auth flows."""

# Azure Artifacts public client application ID (from artifacts-credprovider)
CLIENT_ID = "d5a56ea4-7369-46b8-a538-c370805301bf"

# Azure DevOps resource ID (for az cli --resource flag)
RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798"

# MSAL scope (/.default — narrow scopes not available with first-party client)
SCOPE = [f"{RESOURCE_ID}/.default"]

# Netlocs that indicate an Azure DevOps Artifacts feed
SUPPORTED_NETLOCS = frozenset({
    "pkgs.dev.azure.com",
    "pkgs.visualstudio.com",
    "pkgs.codedev.ms",
    "pkgs.vsts.me",
})
