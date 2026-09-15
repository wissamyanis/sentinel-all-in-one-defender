<#
.SYNOPSIS
    Enables Microsoft Sentinel analytics rules from installed rule templates,
    filtered by severity. This is the Content Hub-era replacement for the
    original v2 EnableRules.ps1 (which enumerated solution rule templates via
    a templateSpecs Resource Graph query that no longer returns them).

.DESCRIPTION
    Sentinel now exposes every installed solution's analytics-rule templates
    through the contentTemplates API (Microsoft.SecurityInsights/contentTemplates).
    This script enumerates those templates, keeps the ones whose severity is in
    -SeveritiesToInclude, and creates an active alert rule for each - linked to
    its template via alertRuleTemplateName, which is what makes the template
    show as "IN USE" in the Content hub.

    It runs entirely with your own Az sign-in (Invoke-AzRestMethod), so it does
    NOT require the Microsoft.Resources/deploymentScripts resource (and the
    storage account keys it needs) that the original v2 template used and that
    many hardened / Defender-onboarded tenants block.

.PARAMETER ResourceGroup
    Resource group that contains the Log Analytics workspace.

.PARAMETER Workspace
    Log Analytics / Sentinel workspace name.

.PARAMETER SeveritiesToInclude
    Severities to enable. Default: High, Medium, Low, Informational.

.PARAMETER Connectors
    Optional. When supplied, a template is only enabled if at least one of its
    required data connectors is in this list. Omit to enable every installed
    template that matches the severity filter (the behaviour most people want).

.PARAMETER WhatIf
    Preview only: report how many rules would be created, per severity, without
    creating anything.

.EXAMPLE
    ./EnableRules.ps1 -ResourceGroup rg-sentinel -Workspace sentinelws -SeveritiesToInclude High,Medium

.EXAMPLE
    ./EnableRules.ps1 -ResourceGroup rg-sentinel -Workspace sentinelws -WhatIf
#>
param(
    [Parameter(Mandatory = $true)][string]$ResourceGroup,
    [Parameter(Mandatory = $true)][string]$Workspace,
    [Parameter(Mandatory = $false)][string[]]$SeveritiesToInclude = @("High", "Medium", "Low", "Informational"),
    [Parameter(Mandatory = $false)][string[]]$Connectors,
    [Parameter(Mandatory = $false)][switch]$WhatIf
)

$ErrorActionPreference = "Stop"

$context = Get-AzContext
if (!$context) {
    Connect-AzAccount | Out-Null
    $context = Get-AzContext
}
$SubscriptionId = $context.Subscription.Id
Write-Host "Connected to subscription: $($context.Subscription.Name) ($SubscriptionId)" -ForegroundColor Cyan

# Normalize severities for case-insensitive comparison
$sevSet = @{}
foreach ($s in $SeveritiesToInclude) { $sevSet[$s.Trim().ToLower()] = $true }

$workspacePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$Workspace"
$alertRulesBase = "$workspacePath/providers/Microsoft.SecurityInsights/alertRules"
$templatesApi = "2023-11-01"
$rulesApi = "2023-02-01"
$rulesApiNRT = "2023-12-01-preview"

function Invoke-Arm {
    param([string]$Path, [string]$FullUri, [string]$Method = "GET", [string]$Payload)
    $params = @{ Method = $Method }
    if ($FullUri) { $params["Uri"] = $FullUri } else { $params["Path"] = $Path }
    if ($Payload) { $params["Payload"] = $Payload }
    return Invoke-AzRestMethod @params
}

Write-Host "Enumerating installed analytics-rule templates (contentTemplates)..." -ForegroundColor Cyan

$templates = New-Object System.Collections.Generic.List[object]
$filter = [System.Uri]::EscapeDataString("properties/contentKind eq 'AnalyticsRule'")
$next = "$workspacePath/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$templatesApi&`$filter=$filter"
$isRelative = $true

while ($next) {
    if ($isRelative) { $resp = Invoke-Arm -Path $next } else { $resp = Invoke-Arm -FullUri $next }
    if ($resp.StatusCode -ne 200) {
        Write-Warning "contentTemplates request returned HTTP $($resp.StatusCode): $($resp.Content)"
        break
    }
    $page = $resp.Content | ConvertFrom-Json
    if ($page.value) { foreach ($v in $page.value) { $templates.Add($v) } }
    if ($page.nextLink) { $next = $page.nextLink; $isRelative = $false } else { $next = $null }
}

Write-Host ("Found {0} installed analytics-rule templates." -f $templates.Count) -ForegroundColor Cyan

# Collect templateNames of rules that already exist, so re-runs are idempotent
# (skip templates that already have an active rule instead of duplicating them).
Write-Host "Checking for already-enabled rules..." -ForegroundColor Cyan
$existingTemplateNames = @{}
$rnext = "$alertRulesBase`?api-version=$rulesApi"
$rIsRelative = $true
while ($rnext) {
    if ($rIsRelative) { $rresp = Invoke-Arm -Path $rnext } else { $rresp = Invoke-Arm -FullUri $rnext }
    if ($rresp.StatusCode -ne 200) { Write-Warning "Could not list existing rules (HTTP $($rresp.StatusCode)); continuing without dedupe."; break }
    $rpage = $rresp.Content | ConvertFrom-Json
    foreach ($r in $rpage.value) {
        $atn = $r.properties.alertRuleTemplateName
        if ($atn) { $existingTemplateNames[$atn] = $true }
    }
    if ($rpage.nextLink) { $rnext = $rpage.nextLink; $rIsRelative = $false } else { $rnext = $null }
}
Write-Host ("  {0} templates already in use (will be skipped)." -f $existingTemplateNames.Count) -ForegroundColor Cyan

$created = 0; $skippedSeverity = 0; $skippedConnector = 0; $skippedKind = 0; $failed = 0
$noMainTemplate = 0; $noRuleResource = 0; $skippedExisting = 0
$createdBySeverity = @{ High = 0; Medium = 0; Low = 0; Informational = 0 }

foreach ($tpl in $templates) {
    $contentId = $tpl.properties.contentId
    $version = $tpl.properties.version
    $main = $tpl.properties.mainTemplate

    # The contentTemplates LIST response omits mainTemplate; fetch the full
    # template by id to get it.
    if (-not $main -and $tpl.id) {
        $g = Invoke-Arm -Path "$($tpl.id)?api-version=$templatesApi"
        if ($g.StatusCode -eq 200) {
            $full = $g.Content | ConvertFrom-Json
            $main = $full.properties.mainTemplate
            if (-not $version) { $version = $full.properties.version }
            if (-not $contentId) { $contentId = $full.properties.contentId }
        }
    }
    if (-not $main) { $noMainTemplate++; continue }

    # The rule inside mainTemplate is typed Microsoft.SecurityInsights/AlertRuleTemplates
    # (not ...alertRules). Match any alert-rule resource, excluding metadata.
    $ruleRes = $main.resources | Where-Object { $_.type -match '(?i)alertrule' } | Select-Object -First 1
    if (-not $ruleRes) { $noRuleResource++; continue }

    $kind = $ruleRes.kind
    if (-not $kind) { $kind = $ruleRes.properties.kind }
    if ($kind -ne 'Scheduled' -and $kind -ne 'NRT') { $skippedKind++; continue }

    $tp = $ruleRes.properties
    $severity = "$($tp.severity)"
    if (-not $severity -or -not $sevSet.ContainsKey($severity.ToLower())) { $skippedSeverity++; continue }

    # Skip templates that already have an active rule (idempotent re-runs)
    if ($contentId -and $existingTemplateNames.ContainsKey($contentId)) { $skippedExisting++; continue }

    # Optional connector gating
    if ($Connectors -and $tp.requiredDataConnectors) {
        $match = $false
        foreach ($rdc in $tp.requiredDataConnectors) {
            if ($rdc.connectorId -and ($Connectors -contains $rdc.connectorId)) { $match = $true; break }
        }
        if (-not $match) { $skippedConnector++; continue }
    }

    if ($WhatIf) {
        $created++
        if ($createdBySeverity.ContainsKey($severity)) { $createdBySeverity[$severity]++ }
        continue
    }

    # templateVersion must be X.Y.Z (all numbers). Prefer the content template
    # version, then the rule's version, then fall back to 1.0.0.
    $tv = "$version"
    if ($tv -notmatch '^\d+\.\d+\.\d+$') { $tv = "$($tp.version)" }
    if ($tv -notmatch '^\d+\.\d+\.\d+$') { $tv = "1.0.0" }

    # Build the alertRules body from a whitelist of valid properties (the template
    # carries fields like requiredDataConnectors/status/version that are not valid
    # on an alertRules PUT and would cause 400s).
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
        # The API allows at most 5 entity mappings; some templates ship more.
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

    $body = @{ kind = $kind; properties = $ruleProps }

    $guid = [guid]::NewGuid().ToString()
    $api = if ($kind -eq 'NRT') { $rulesApiNRT } else { $rulesApi }
    $ruleUri = "$alertRulesBase/$guid`?api-version=$api"
    try {
        $put = Invoke-Arm -Path $ruleUri -Method "PUT" -Payload ($body | ConvertTo-Json -Depth 20)
        if ($put.StatusCode -ge 200 -and $put.StatusCode -lt 300) {
            $created++
            if ($createdBySeverity.ContainsKey($severity)) { $createdBySeverity[$severity]++ }
            Write-Host ("  + [{0}] {1}" -f $severity, $tp.displayName) -ForegroundColor Green
        }
        else {
            $failed++
            Write-Warning ("  ! Failed [{0}] {1} -> HTTP {2}: {3}" -f $severity, $tp.displayName, $put.StatusCode, $put.Content)
        }
    }
    catch {
        $failed++
        Write-Warning ("  ! Error [{0}] {1} -> {2}" -f $severity, $tp.displayName, $_.Exception.Message)
    }
}

Write-Host ""
if ($WhatIf) {
    Write-Host "WHATIF: would create $created rules." -ForegroundColor Yellow
}
else {
    Write-Host "Done. Created $created rules." -ForegroundColor Cyan
}
Write-Host ("  By severity: High={0} Medium={1} Low={2} Informational={3}" -f $createdBySeverity.High, $createdBySeverity.Medium, $createdBySeverity.Low, $createdBySeverity.Informational)
Write-Host ("  Skipped: severity={0} connector={1} kind(non-Scheduled/NRT)={2} alreadyInUse={3} noMainTemplate={4} noRuleResource={5}  Failed: {6}" -f $skippedSeverity, $skippedConnector, $skippedKind, $skippedExisting, $noMainTemplate, $noRuleResource, $failed)
Write-Host ""
Write-Host "Note: some Microsoft templates query tables you may not be ingesting yet; those individual rules can fail and are counted under 'Failed'. That is expected and does not stop the rest."
