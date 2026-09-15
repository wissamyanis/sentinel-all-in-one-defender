# Sentinel Accelerated All-in-One ---- Preview ----

![Sentinel Accelerated All-in-One](./media/SentinelAcceleratedLogo.png)

> Personal fork of [Javier Soriano's Sentinel All-in-One](https://github.com/javiersoriano/sentinel-all-in-one), re-worked for the unified **Microsoft Defender portal** era. All original authorship and credit belong to Javier Soriano.

> ⚠️ Personal community project — not an official/supported Microsoft product. Provided "as is", use at your own risk. See [Disclaimer & license](#disclaimer--license).

## Purpose

A **Sentinel adoption accelerator for the field**. It lets a Solution Engineer deploy a working, customer-ready Microsoft Sentinel — workspace, data connectors, ingestion, Content Hub content, and analytics rules already switched on — in about **15 minutes, live during a customer meeting**. The customer leaves with a functioning SIEM starting point they own and can extend.

It is built for the **Microsoft Defender portal** era: it deploys only what Azure Resource Manager (ARM) still owns, and defers the connectors that the Defender portal now manages — so it deploys cleanly on modern Defender-connected tenants where the original Azure-portal-era tool fails.

> **Timeline:** Microsoft Sentinel is generally available in the Microsoft Defender portal (no Defender XDR or E5 license required). After **March 31, 2027**, Microsoft Sentinel is no longer supported in the Azure portal — the Defender portal becomes the only experience. This tool deploys via ARM, which is unaffected by that UX retirement.

## The connector model (Defender era)

Once a workspace is onboarded to the Defender portal (which is automatic for many workspaces created after July 2025), the Microsoft Defender family connectors are **managed by Defender** and can no longer be created or changed through ARM/Sentinel. This tool splits connectors accordingly:

**Deployed by this tool (ARM-safe):**

| Connector | How | Notes |
| --- | --- | --- |
| Azure Activity | Subscription diagnostic setting | Default. Fast, visible data. |
| Microsoft Defender for Cloud | Sentinel connector | Default. |
| Office 365 | Sentinel connector | Default. |
| Windows Security Events (AMA) | Data Collection Rule | Default. Attach AMA to machines to collect. |
| Microsoft Entra ID (sign-in & audit logs) | Tenant diagnostic settings | Streams SigninLogs/AuditLogs (choose from 12 log categories in the wizard); powers the identity analytics rules. Global Admin required. |
| Common Event Format (CEF) / Syslog (AMA) | Data Collection Rule | For firewalls/appliances (e.g. Palo Alto). Attach a Linux forwarder. |
| Dynamics 365, Power BI, Project, Purview IRM | Sentinel connector | Only if the tenant is licensed. |

Threat indicator ingestion is delivered via the **Threat Intelligence Content Hub solution** (installed from the Solutions step), not a data connector. The Microsoft Defender Threat Intelligence feed connectors are deliberately **not** included: they require tenant **CFAR onboarding approval** that ARM cannot grant, so on a non-approved tenant they fail with `Forbidden: tenant is not approved for MicrosoftTi connector onboarding` and break the whole deployment. The original upstream project ships no TI data connector either, so this keeps parity with upstream.

**Not deployed by this tool (managed by the Defender portal, enabled automatically when the workspace joins Defender):**

- Microsoft Defender XDR, Defender for Endpoint, Defender for Identity, Defender for Cloud Apps, Defender for Office 365
- Microsoft Defender for IoT (requires the Defender for IoT plan to be provisioned)

These are intentionally **not** in the wizard: attempting to deploy them via ARM on a Defender-connected workspace fails. They light up automatically in the Defender portal instead.

## What the template does

1. Creates the resource group and the Log Analytics workspace.
2. Enables Microsoft Sentinel on the workspace (unified/simplified billing).
3. Sets retention, daily cap, and pricing tier (Pay-as-you-go or a Commitment Tier from 50 GB/day up).
4. Enables UEBA and health diagnostics.
5. Installs a curated set of Content Hub solutions.
6. Enables the selected ARM-safe data connectors (see above).
7. Enables analytics rules as **native ARM resources** — Microsoft incident-creation rules plus a curated set of scheduled KQL detections. No deployment script, no managed identity, no storage account, so it works under strict storage policies.

Deploys at **subscription scope** (creates its own resource group); requires **Owner or Contributor on the subscription**. Typical run is ~10-15 minutes.

## Deploy

> The **Deploy to Azure** button requires this repository to be **Public** (the Azure portal fetches the templates from `raw.githubusercontent.com`).

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fwissamyanis%2Fsentinel-all-in-one-defender%2Fmain%2Fazuredeploy-v3.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fwissamyanis%2Fsentinel-all-in-one-defender%2Fmain%2FcreateUiDefinition.json)

Click the button, complete the wizard (Basics, Settings, Content Hub Solutions, Data connectors, Analytics rules), and deploy.

**Tips for a reliable live demo:**
- Use a **new resource group** and a **workspace name you have not used before** (deleted workspace names are soft-reserved for 14 days and can collide).
- After pushing template changes to GitHub, allow a few minutes for the raw CDN cache to refresh, and fully reload the Deploy blade, before deploying.
- Keep the default connector selection for a guaranteed-green deploy; add license-gated connectors only when you know the tenant supports them (a failing connector fails the whole deployment).

## Connecting the workspace to the Defender portal

There is no supported ARM/API to connect a workspace to the Defender portal — it is a portal action, and workspaces onboarded to Sentinel after July 1, 2025 are often connected automatically. `Scripts/Connect-DefenderPortal.ps1` verifies readiness (workspace exists, Sentinel enabled) and prints the remaining portal step and required roles:

```powershell
./Scripts/Connect-DefenderPortal.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -WorkspaceName <workspace>
```

See [Connect Microsoft Sentinel to the Defender portal](https://learn.microsoft.com/en-us/unified-secops/microsoft-sentinel-onboard).

## Repository layout

```
azuredeploy-v3.json          Main deployment template (entry point, subscription scope)
createUiDefinition.json      Portal wizard UI
DEFENDER-CHANGES.md          Details of the Defender-era changes
LinkedTemplates/             Workspace, settings, solutions, connectors, DCRs, analytics rules
Scripts/                     Connect-DefenderPortal.ps1, EnableRules.ps1
media/                       Logo and assets
```

## Credits

Based on the original [Sentinel All-in-One](https://github.com/javiersoriano/sentinel-all-in-one) by **Javier Soriano** and the Microsoft Sentinel community, re-worked for the Microsoft Defender portal era.

## Disclaimer & license

> <sub>THIS PROJECT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. It is a personal, community contribution and is **not** an official Microsoft product or offering. It is **not** supported, endorsed, certified, or maintained by Microsoft Corporation, and the views and code here do not represent Microsoft. Microsoft names, products, and services are referenced for descriptive purposes only and are trademarks of Microsoft Corporation.</sub>
>
> <sub>Neither the author nor Microsoft is responsible or liable for any direct, indirect, incidental, or consequential damages, data loss, security exposure, service disruption, licensing issues, or Azure/cloud charges resulting from the use of this project. **Use it entirely at your own risk.** You are solely responsible for reviewing and testing the templates in a non-production environment and for ensuring compliance with your organization's security, governance, licensing, and cost policies before any use.</sub>
>
> <sub>Licensed under the [MIT License](./LICENSE).</sub>

