# Defender-era changes (fork vs. upstream)

This fork of [javiersoriano/sentinel-all-in-one](https://github.com/javiersoriano/sentinel-all-in-one) modernizes the deployment for the **unified Microsoft Defender portal** era. Sentinel still runs on Azure (a Log Analytics workspace with Sentinel enabled); the Defender portal (security.microsoft.com) is the operational front end. The upstream template was written for the Azure-portal era and fails on modern, Defender-onboarded tenants because most of its connectors are now **Defender-managed** and can no longer be created or changed through ARM.

This document explains, connector by connector, what changed and why.

## The connector model in the Defender era

Once a workspace is onboarded to the Defender portal (automatic for many workspaces created after **July 1, 2025**), the Microsoft Defender family connectors are owned by Defender. Creating them via ARM returns:

```
BadRequest: The workspace is enabled through the Microsoft Threat Protection Portal.
Changes to the connector in Microsoft Sentinel are disabled.
```

So the fork deploys **only what ARM still owns** and lets the Defender-managed connectors light up automatically in the portal.

## Connector comparison: upstream vs. this fork

| Connector | Upstream (`kind`) | This fork | Why |
| --- | --- | --- | --- |
| Azure Activity | `AzureActivityLog` dataSource (retired) | **Subscription-scope `Microsoft.Insights/diagnosticSettings`** | Legacy dataSource API is deprecated. Modern diagnostic-setting path is the supported way to stream the Activity Log. |
| Windows Security Events | `SecurityInsightsSecurityEventCollectionConfiguration` (MMA tier) | **AMA Data Collection Rule** (`LinkedTemplates/dataCollectionRules.json`) | The MMA/OMS agent is retired. Collection now uses the Azure Monitor Agent driven by a DCR (All / Common / Minimal event sets). |
| CEF / Syslog | `LinuxSyslogCollection` dataSource | **AMA DCRs** (`dataCollectionRules-CEF.json`) | Same MMA retirement. CEF and Syslog now flow through AMA + DCR (attach a Linux forwarder). |
| Microsoft Entra ID | `AzureActiveDirectory` **connector** | **`microsoft.aadiam/diagnosticSettings`** (12 selectable log categories) | The Sentinel Entra ID *connector* is Defender-managed and blocked via ARM. Tenant diagnostic settings are the non-blocked path for SigninLogs/AuditLogs/etc. and still power the identity analytics rules. |
| Microsoft Defender for Cloud | `AzureSecurityCenter` | **Kept** (`AzureSecurityCenter`) | Still ARM-deployable. Default connector. |
| Office 365 | `Office365` | **Kept** (`Office365`) | Still ARM-deployable. Default connector. |
| Dynamics 365 / Power BI / Project / Purview IRM | `Dynamics365` / `OfficePowerBI` / `Office365Project` / `OfficeIRM` | **Kept** (license-gated) | Still ARM-deployable when the tenant is licensed. |
| WindowsFirewall / DNS | `OMSGallery/WindowsFirewall`, `OMSGallery/DnsAnalytics` solutions | **Dropped** | Legacy OMS gallery solutions; the gallery is retired. Superseded by Content Hub. |
| Microsoft Defender for Endpoint | `MicrosoftDefenderAdvancedThreatProtection` | **Not exposed** (Defender-managed) | Blocked via ARM on onboarded workspaces; lights up automatically in the Defender portal. |
| Microsoft Defender for Identity | `AzureAdvancedThreatProtection` | **Not exposed** (Defender-managed) | Same. |
| Microsoft Defender for Cloud Apps | `MicrosoftCloudAppSecurity` | **Not exposed** (Defender-managed) | Same. |
| Microsoft Defender XDR | *(n/a)* | **Not exposed** (Defender-managed) | The unified portal streams XDR incidents/alerts natively once onboarded. |
| Threat Intelligence (all forms) | *(none in upstream)* | **Removed** | The fork briefly added `ThreatIntelligence`, `MicrosoftThreatIntelligence`, and `PremiumMicrosoftDefenderForThreatIntelligence`. The two MDTI feeds require tenant **CFAR onboarding approval** ARM cannot grant (`Forbidden: tenant is not approved for MicrosoftTi connector onboarding`), so all three were removed to keep parity with upstream. Threat-intel content ships via the **Content Hub "Threat Intelligence" solution** instead. |

### What the wizard deploys now (ARM-safe set)

Default (pre-selected): **Azure Activity, Microsoft Defender for Cloud, Office 365, Windows Security Events (AMA)**.

Also selectable: **Microsoft Entra ID (diagnostic settings), CEF via AMA, Syslog via AMA, Dynamics 365, Power BI, Project, Purview Insider Risk Management**.

> A failing connector fails the whole deployment. Keep the defaults for a guaranteed-green live deploy; add license-gated connectors only when you know the tenant supports them.

## Deployment fixes applied during live testing

The fork was hardened against ~15 real failures hit on a Defender-connected, policy-strict tenant:

1. **Scope** — parent template runs at **subscription** scope (Activity Log diagnostic setting needs it).
2. **Unified billing** — removed the separate Sentinel pricing SKU; workspace uses unified billing.
3. **AzureActivityLog deprecated** -> subscription diagnostic setting.
4. **MMA retired** -> AMA + DCR for Windows Security Events, CEF, and Syslog.
5. **DCR xPath limit** — Windows event queries chunked to <=20 xPath expressions per query.
6. **Deployment-script rules blocked** — the tenant's storage shared-key policy blocked `deploymentScripts`; analytics rules were rewritten as **native, script-free** `alertRules` resources.
7. **Entra ID connector blocked** -> `microsoft.aadiam/diagnosticSettings` only (SigninLogs/AuditLogs + 10 more categories).
8. **Diagnostic-settings timing** — reference the workspace resource ID from the workspace deployment output and `dependsOn` the connector step.
9. **Fusion is a singleton** — removed (can't be created per-deploy).
10. **MDTI/TI CFAR gate** — removed the TI connectors entirely (see table).
11. **Analytics rules gating** — `enableScheduledAlerts` now defaults **true**; three identity KQL rules deploy unconditionally so a fresh deploy always shows active rules.
12. **Scheduled-rule schema** — `triggerOperator` uses full words (`GreaterThan`), `suppressionDuration` always present, api `2023-02-01`.
13. **Content Hub "Updates"** — solutions install from the GitHub `master` mainTemplate.json so they show current, not "Updates".
14. **Soft-delete reservation** — deleted workspace names are reserved 14 days; use a fresh RG + new workspace name when redeploying.
15. **CDN staleness** — `raw.githubusercontent.com` caches ~5-10 min; wait after pushing before deploying.

## Connecting the workspace to the Defender portal

There is no supported ARM/API to connect a workspace to the Defender portal — it is a portal action (automatic for many post-July-2025 workspaces). `Scripts/Connect-DefenderPortal.ps1` verifies readiness (workspace exists, Sentinel enabled) and prints the remaining portal step and required roles.

```powershell
./Scripts/Connect-DefenderPortal.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -WorkspaceName <workspace>
```

Onboarding requires **Security Administrator** (Entra ID) plus **Owner**, or **User Access Administrator + Microsoft Sentinel Contributor**, at subscription scope. See [Connect Microsoft Sentinel to the Defender portal](https://learn.microsoft.com/en-us/unified-secops/microsoft-sentinel-onboard).

## Deploy

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fwissamyanis%2Fsentinel-all-in-one-defender%2Fmain%2Fazuredeploy-v3.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fwissamyanis%2Fsentinel-all-in-one-defender%2Fmain%2FcreateUiDefinition.json)
