<#
.SYNOPSIS
    Verifies that a Microsoft Sentinel workspace is ready to be used in the unified
    Microsoft Defender portal, and reports the remaining onboarding step.

.DESCRIPTION
    As of GA there is no supported ARM/Bicep resource that programmatically "connects"
    a Sentinel workspace to the Defender portal. The connection is performed in the
    Defender portal (Settings > Microsoft Sentinel > SIEM workspaces > Connect workspace).
    Workspaces onboarded to Microsoft Sentinel after July 1, 2025 are, in many cases,
    onboarded to the Defender portal automatically.

    This helper does the part that CAN be automated/verified:
      1. Confirms the Log Analytics workspace exists.
      2. Confirms Microsoft Sentinel is enabled on it (onboardingStates/default).
      3. Confirms the Microsoft Defender XDR connector (MicrosoftThreatProtection) is present,
         which is the recommended connector for the unified experience.
      4. Prints the exact remaining portal step and the required roles.

    Ref: https://learn.microsoft.com/en-us/unified-secops/microsoft-sentinel-onboard

.PARAMETER SubscriptionId
    Subscription that contains the workspace.

.PARAMETER ResourceGroup
    Resource group that contains the workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace with Microsoft Sentinel enabled.

.EXAMPLE
    ./Connect-DefenderPortal.ps1 -SubscriptionId <sub> -ResourceGroup rg-sentinel -WorkspaceName siemsoc
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $SubscriptionId,
    [Parameter(Mandatory = $true)] [string] $ResourceGroup,
    [Parameter(Mandatory = $true)] [string] $WorkspaceName
)

$ErrorActionPreference = 'Stop'

function Get-Token {
    # Requires an authenticated Az context (Connect-AzAccount).
    (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
}

if (-not (Get-AzContext)) {
    Write-Host 'No Azure context found. Running Connect-AzAccount...' -ForegroundColor Yellow
    Connect-AzAccount -Subscription $SubscriptionId | Out-Null
}
Set-AzContext -Subscription $SubscriptionId | Out-Null

$headers = @{ Authorization = "Bearer $(Get-Token)" }
$base    = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers"
$wsId    = "$base/Microsoft.OperationalInsights/workspaces/$WorkspaceName"

$ok = $true

# 1. Workspace exists
try {
    Invoke-RestMethod -Method Get -Headers $headers -Uri "${wsId}?api-version=2023-09-01" | Out-Null
    Write-Host "[PASS] Log Analytics workspace '$WorkspaceName' found." -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Workspace '$WorkspaceName' not found in RG '$ResourceGroup'." -ForegroundColor Red
    $ok = $false
}

# 2. Sentinel enabled (onboarding state)
if ($ok) {
    try {
        Invoke-RestMethod -Method Get -Headers $headers `
            -Uri "$wsId/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-09-01" | Out-Null
        Write-Host "[PASS] Microsoft Sentinel is enabled on the workspace." -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Microsoft Sentinel is not enabled on this workspace. Enable it first." -ForegroundColor Red
        $ok = $false
    }
}

# 3. Defender XDR connector present
if ($ok) {
    try {
        $conns = Invoke-RestMethod -Method Get -Headers $headers `
            -Uri "$wsId/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2025-09-01"
        $xdr = $conns.value | Where-Object { $_.kind -eq 'MicrosoftThreatProtection' }
        if ($xdr) {
            Write-Host "[PASS] Microsoft Defender XDR connector (MicrosoftThreatProtection) is enabled." -ForegroundColor Green
        } else {
            Write-Host "[WARN] Microsoft Defender XDR connector not found. Enable the 'Microsoft Defender XDR' connector for the best unified-portal experience." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[WARN] Could not enumerate data connectors: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host '================ Defender portal onboarding ================' -ForegroundColor Cyan
Write-Host 'There is no supported ARM/API to connect a workspace to the Defender portal.'
Write-Host 'Complete the final step in the portal (or confirm auto-onboarding):'
Write-Host ''
Write-Host '  1. Go to https://security.microsoft.com'
Write-Host '  2. Settings > Microsoft Sentinel > SIEM workspaces'
Write-Host "  3. Select workspace '$WorkspaceName' and choose 'Connect workspace'"
Write-Host ''
Write-Host 'Required roles to onboard:' -ForegroundColor Cyan
Write-Host '  - Security Administrator (Microsoft Entra ID), AND'
Write-Host '  - Owner (unconditional) at the subscription scope'
Write-Host '    OR User Access Administrator + Microsoft Sentinel Contributor'
Write-Host ''
Write-Host 'Note: Workspaces onboarded to Sentinel after July 1, 2025 are often connected automatically.'
Write-Host 'Docs: https://learn.microsoft.com/en-us/unified-secops/microsoft-sentinel-onboard'
Write-Host '==========================================================='
