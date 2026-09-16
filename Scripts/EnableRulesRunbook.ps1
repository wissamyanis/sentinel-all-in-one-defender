<#
.SYNOPSIS
    Azure Automation runbook version of EnableRules.ps1.

.DESCRIPTION
    Enables Microsoft Sentinel analytics rules from installed Content Hub rule
    templates, filtered by severity and by the connectors selected at deployment
    time. Designed to run inside an Azure Automation Account using the account's
    system-assigned managed identity.

    Unlike the deploymentScripts path, this does NOT require a storage account or
    storage account keys - it runs in Azure Automation's managed sandbox and gets
    an ARM token from the managed-identity endpoint (IDENTITY_ENDPOINT), so it
    works on tenants that block storage key authentication.

    Parameters are passed as strings (Automation job parameters). Severities and
    DeploymentConnectors are comma-separated.
#>
param(
    [Parameter(Mandatory = $true)][string]$SubscriptionId,
    [Parameter(Mandatory = $true)][string]$ResourceGroup,
    [Parameter(Mandatory = $true)][string]$Workspace,
    [Parameter(Mandatory = $false)][string]$Severities = "High,Medium",
    [Parameter(Mandatory = $false)][string]$DeploymentConnectors = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Output "EnableRules runbook starting for workspace '$Workspace' (RG '$ResourceGroup', sub '$SubscriptionId')."

# Give the role assignment time to propagate before the identity is used.
Start-Sleep -Seconds 60

# ---- Managed-identity ARM token (no Az module, no storage) ----
function Get-MgmtToken {
    $resourceURI = "https://management.azure.com/"
    $uri = "$($env:IDENTITY_ENDPOINT)?resource=$resourceURI&api-version=2019-08-01"
    $resp = Invoke-RestMethod -Method Get -Headers @{ "X-IDENTITY-HEADER" = $env:IDENTITY_HEADER } -Uri $uri
    return $resp.access_token
}
$script:token = Get-MgmtToken
function Auth { return @{ Authorization = "Bearer $script:token"; "Content-Type" = "application/json" } }

# ---- Robust ARM call: never throws, retries transient errors ----
function Invoke-Arm {
    param([string]$Uri, [string]$Method = "GET", [string]$Body, [int]$MaxRetries = 5)
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $p = @{ Uri = $Uri; Method = $Method; Headers = (Auth); UseBasicParsing = $true }
            if ($Body) { $p.Body = $Body }
            $r = Invoke-WebRequest @p
            return @{ StatusCode = [int]$r.StatusCode; Content = "$($r.Content)" }
        }
        catch {
            $code = 0
            if ($_.Exception.Response) { try { $code = [int]$_.Exception.Response.StatusCode.value__ } catch {} }
            $body = ""
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $body = "$($_.ErrorDetails.Message)" }
            # Refresh token on 401, retry transient
            if ($code -eq 401 -and $attempt -lt $MaxRetries) { $script:token = Get-MgmtToken; Start-Sleep -Seconds 5; continue }
            if (($code -eq 429 -or $code -ge 500 -or $code -eq 0) -and $attempt -lt $MaxRetries) {
                Start-Sleep -Seconds ([Math]::Min(60, [Math]::Pow(2, $attempt))); continue
            }
            return @{ StatusCode = $code; Content = $body }
        }
    }
}

$sevSet = @{}
foreach ($s in ($Severities -split ',')) { if ($s.Trim()) { $sevSet[$s.Trim().ToLower()] = $true } }

$connectorMap = @{
    "azureactivity"             = @("AzureActivity")
    "microsoftdefenderforcloud" = @("AzureSecurityCenter")
    "office365"                 = @("Office365")
    "securityevents"            = @("SecurityEvents", "WindowsSecurityEvents")
    "azureactivedirectory"      = @("AzureActiveDirectory", "AzureActiveDirectoryIdentityProtection")
    "cefviaama"                 = @("CEF", "CommonSecurityLog")
    "syslogviaama"              = @("Syslog")
    "dynamics365"               = @("Dynamics365")
    "officepowerbi"             = @("OfficePowerBI", "PowerBI")
    "office365project"          = @("Office365Project")
    "officeirm"                 = @("OfficeIRM", "MicrosoftPurviewInsiderRiskManagement")
    "threatintelligence"        = @("ThreatIntelligence", "ThreatIntelligenceTaxii")
}
$allowedConnectorIds = $null
if ($DeploymentConnectors.Trim()) {
    $allowedConnectorIds = @{}
    foreach ($c in ($DeploymentConnectors -split ',')) {
        $key = $c.Trim().ToLower()
        if (-not $key) { continue }
        $allowedConnectorIds[$key] = $true
        if ($connectorMap.ContainsKey($key)) { foreach ($m in $connectorMap[$key]) { $allowedConnectorIds[$m.ToLower()] = $true } }
    }
    Write-Output "Gating on selected connectors: $DeploymentConnectors"
}

$mgmt = "https://management.azure.com"
$workspacePath = "$mgmt/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$Workspace"
$alertRulesBase = "$workspacePath/providers/Microsoft.SecurityInsights/alertRules"
$templatesApi = "2023-11-01"
$rulesApi = "2023-02-01"
$rulesApiNRT = "2023-12-01-preview"

# ---- Enumerate installed analytics-rule templates ----
Write-Output "Enumerating installed analytics-rule templates..."
$templates = New-Object System.Collections.Generic.List[object]
$filter = [System.Uri]::EscapeDataString("properties/contentKind eq 'AnalyticsRule'")
$next = "$workspacePath/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$templatesApi&`$filter=$filter"
while ($next) {
    $resp = Invoke-Arm -Uri $next
    if ($resp.StatusCode -ne 200) { Write-Warning "contentTemplates HTTP $($resp.StatusCode): $($resp.Content)"; break }
    $page = $null
    try { $page = $resp.Content | ConvertFrom-Json } catch { Write-Warning "parse error; stopping enumeration"; break }
    if ($page.value) { foreach ($v in $page.value) { $templates.Add($v) } }
    if ($page.nextLink) { $next = $page.nextLink } else { $next = $null }
}
Write-Output "Found $($templates.Count) installed analytics-rule templates."

# ---- Existing rules (idempotent) ----
$existing = @{}
$rnext = "$alertRulesBase`?api-version=$rulesApi"
while ($rnext) {
    $rresp = Invoke-Arm -Uri $rnext
    if ($rresp.StatusCode -ne 200) { Write-Warning "list existing rules HTTP $($rresp.StatusCode); continuing without dedupe"; break }
    $rpage = $null
    try { $rpage = $rresp.Content | ConvertFrom-Json } catch { break }
    foreach ($r in $rpage.value) { $atn = $r.properties.alertRuleTemplateName; if ($atn) { $existing[$atn] = $true } }
    if ($rpage.nextLink) { $rnext = $rpage.nextLink } else { $rnext = $null }
}
Write-Output "$($existing.Count) templates already in use (will be skipped)."

$created = 0; $skippedSeverity = 0; $skippedConnector = 0; $skippedKind = 0
$skippedExisting = 0; $noMain = 0; $noRule = 0; $failed = 0

foreach ($tpl in $templates) {
    $contentId = $tpl.properties.contentId
    $version = $tpl.properties.version
    $main = $tpl.properties.mainTemplate
    if (-not $main -and $tpl.id) {
        $g = Invoke-Arm -Uri "$mgmt$($tpl.id)?api-version=$templatesApi"
        if ($g.StatusCode -eq 200) {
            try { $full = $g.Content | ConvertFrom-Json; $main = $full.properties.mainTemplate; if (-not $version) { $version = $full.properties.version }; if (-not $contentId) { $contentId = $full.properties.contentId } } catch { $main = $null }
        }
    }
    if (-not $main) { $noMain++; continue }

    $ruleRes = $main.resources | Where-Object { $_.type -match '(?i)alertrule' } | Select-Object -First 1
    if (-not $ruleRes) { $noRule++; continue }

    $kind = $ruleRes.kind
    if (-not $kind) { $kind = $ruleRes.properties.kind }
    if ($kind -ne 'Scheduled' -and $kind -ne 'NRT') { $skippedKind++; continue }

    $tp = $ruleRes.properties
    $severity = "$($tp.severity)"
    if (-not $severity -or -not $sevSet.ContainsKey($severity.ToLower())) { $skippedSeverity++; continue }
    if ($contentId -and $existing.ContainsKey($contentId)) { $skippedExisting++; continue }

    if ($allowedConnectorIds -and $tp.requiredDataConnectors) {
        $match = $false
        foreach ($rdc in $tp.requiredDataConnectors) {
            if ($rdc.connectorId -and $allowedConnectorIds.ContainsKey(("$($rdc.connectorId)").ToLower())) { $match = $true; break }
        }
        if (-not $match) { $skippedConnector++; continue }
    }

    $tv = "$version"
    if ($tv -notmatch '^\d+\.\d+\.\d+$') { $tv = "$($tp.version)" }
    if ($tv -notmatch '^\d+\.\d+\.\d+$') { $tv = "1.0.0" }

    $ruleProps = @{
        enabled               = $true
        alertRuleTemplateName = $contentId
        templateVersion       = $tv
        displayName           = $tp.displayName
        description           = $tp.description
        severity              = $severity
        suppressionDuration   = "PT5H"
        suppressionEnabled    = $false
    }
    if ($null -ne $tp.query) { $ruleProps["query"] = $tp.query }
    if ($null -ne $tp.tactics) { $ruleProps["tactics"] = $tp.tactics }
    if ($null -ne $tp.techniques) { $ruleProps["techniques"] = $tp.techniques }
    if ($null -ne $tp.entityMappings) {
        $em = @($tp.entityMappings)
        if ($em.Count -gt 5) { $em = $em[0..4] }
        $ruleProps["entityMappings"] = $em
    }
    if ($null -ne $tp.eventGroupingSettings) { $ruleProps["eventGroupingSettings"] = $tp.eventGroupingSettings }
    if ($null -ne $tp.customDetails) { $ruleProps["customDetails"] = $tp.customDetails }
    if ($null -ne $tp.alertDetailsOverride) { $ruleProps["alertDetailsOverride"] = $tp.alertDetailsOverride }
    if ($null -ne $tp.incidentConfiguration) { $ruleProps["incidentConfiguration"] = $tp.incidentConfiguration }
    if ($kind -eq 'Scheduled') {
        if ($null -ne $tp.queryFrequency) { $ruleProps["queryFrequency"] = $tp.queryFrequency }
        if ($null -ne $tp.queryPeriod) { $ruleProps["queryPeriod"] = $tp.queryPeriod }
        if ($null -ne $tp.triggerOperator) { $ruleProps["triggerOperator"] = $tp.triggerOperator }
        if ($null -ne $tp.triggerThreshold) { $ruleProps["triggerThreshold"] = $tp.triggerThreshold }
    }

    $body = @{ kind = $kind; properties = $ruleProps } | ConvertTo-Json -Depth 20
    $guid = [guid]::NewGuid().ToString()
    $api = if ($kind -eq 'NRT') { $rulesApiNRT } else { $rulesApi }
    $put = Invoke-Arm -Uri "$alertRulesBase/$guid`?api-version=$api" -Method "PUT" -Body $body
    if ($put.StatusCode -ge 200 -and $put.StatusCode -lt 300) {
        $created++
        Write-Output "  + [$severity] $($tp.displayName)"
    }
    else {
        $failed++
        Write-Warning "  ! Failed [$severity] $($tp.displayName) -> HTTP $($put.StatusCode): $($put.Content)"
    }
}

Write-Output ""
Write-Output "Done. Created $created rules."
Write-Output "  Skipped: severity=$skippedSeverity connector=$skippedConnector kind=$skippedKind alreadyInUse=$skippedExisting noMainTemplate=$noMain noRuleResource=$noRule  Failed: $failed"
Write-Output "Note: templates whose query references a table you are not ingesting fail individually and are expected."
