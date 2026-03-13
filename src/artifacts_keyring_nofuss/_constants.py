"""Constants shared across auth flows."""

# Azure DevOps resource ID (for az cli --resource flag)
RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798"

# Netlocs that indicate an Azure DevOps Artifacts feed
SUPPORTED_NETLOCS = frozenset({
    "pkgs.dev.azure.com",
    "pkgs.visualstudio.com",
    "pkgs.codedev.ms",
    "pkgs.vsts.me",
})
