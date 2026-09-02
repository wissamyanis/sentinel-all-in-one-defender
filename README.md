# Sentinel Accelerated All-in-One

![Sentinel Accelerated All-in-One](./media/SentinelAcceleratedLogo.png)

> Personal copy of [Javier Soriano's Sentinel All-in-One](https://github.com/javiersoriano/sentinel-all-in-one), extended for the unified **Microsoft Defender portal**. All original authorship and credit belong to Javier Soriano.

Sentinel Accelerated All-in-One speeds up the deployment and initial configuration of a Microsoft Sentinel environment. It is ideal for Proof of Concept scenarios and connector onboarding when highly privileged users are needed. This edition is updated for the era where Microsoft Sentinel runs in the unified **Microsoft Defender portal** (`security.microsoft.com`).

Microsoft Sentinel is still deployed on Azure (a Log Analytics workspace with Sentinel enabled). The Defender portal is the operational front end. This template provisions everything on Azure the same way, and adds the connector and collection changes that come with the move to the Defender portal.

## What is new in this edition

- Data connector API versions bumped to GA `2025-09-01`
- New connectors: **Microsoft Defender Threat Intelligence** and **Premium MDTI** (replacing the deprecated Threat Intelligence Platforms connector for new deployments)
- "Microsoft 365 Defender" relabeled **Microsoft Defender XDR** (the central connector for the unified portal)
- **Windows Security Events via AMA** using a Data Collection Rule (All / Common / Minimal event sets) — the modern replacement for the retired Log Analytics agent (MMA/OMS)
- Optional modern subscription-scope **Azure Activity** connector (diagnostic-setting based)
- `Scripts/Connect-DefenderPortal.ps1` to verify readiness and guide Defender portal onboarding

For the full technical detail of every change, see [DEFENDER-CHANGES.md](./DEFENDER-CHANGES.md).

## Prerequisites

- An Azure subscription.
- An Azure user account with enough permissions to enable the desired connectors (see the table below). Write permissions to the workspace are **always** needed.
- Some data connectors require the relevant license in order to be enabled (see the table below).

The following table summarizes the license, permissions and cost to enable each data connector in this edition:

| Data Connector | License | Permissions | Cost |
| --- | --- | --- | --- |
| Azure Active Directory | Any Entra ID license | Global Admin or Security Admin | Billed |
| Azure Active Directory Identity Protection | Entra ID Premium 2 | Global Admin or Security Admin | Free |
| Azure Activity | None | Subscription Reader | Free |
| Dynamics 365 | D365 license | Global Admin or Security Admin | Billed |
| Microsoft Defender XDR | M365 E5 / equivalent | Global Admin or Security Admin | Free |
| Microsoft Defender for Cloud | Defender for Cloud | Security Reader | Free |
| Microsoft Insider Risk Management | IRM license | Global Admin or Security Admin | Free |
| Microsoft Power BI | Power BI license | Global Admin or Security Admin | Billed |
| Microsoft Project | Project license | Global Admin or Security Admin | Billed |
| Office 365 | None | Global Admin or Security Admin | Free |
| Security Events via AMA (Windows) | None | Monitoring Contributor (for the DCR) | Billed |
| Microsoft Defender Threat Intelligence | None | Global Admin or Security Admin | Free |
| Premium Microsoft Defender Threat Intelligence | MDTI Premium | Global Admin or Security Admin | Billed |
| Threat Intelligence Platforms (legacy) | None | Global Admin or Security Admin | Billed |

## What the template does

The template performs the following tasks:

1. Creates the resource group (if it does not exist yet).
2. Creates the Log Analytics workspace (if it does not exist yet).
3. Installs Microsoft Sentinel on top of the workspace (if not installed yet).
4. Sets workspace retention, daily cap and commitment tiers if desired.
5. Enables UEBA with the relevant identity providers.
6. Enables health diagnostics for Analytics Rules, Data Connectors and Automation Rules.
7. Installs Content Hub solutions from a predefined list.
8. Enables the selected data connectors (see list above), including **Windows Security Events via AMA** as a Data Collection Rule.
9. Enables analytics rules (Scheduled, NRT, Fusion, ML Behavior Analytics) for the selected solutions and connectors, with the ability to filter by severity.

It takes around 10 minutes to deploy. To create the scheduled analytics rules the template uses a [deployment script](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deployment-script-template), which requires a [managed identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview). You will see this resource in your resource group when the deployment finishes; you can remove it afterwards if desired.

## Deploy

> The **Deploy to Azure** button requires this repository to be **Public** — the Azure portal fetches the templates from `raw.githubusercontent.com`. While the repo is Private, use the CLI method below or the [CreateUIDefinition Sandbox](https://portal.azure.com/#view/Microsoft_Azure_CreateUIDef/SandboxBlade) to preview the wizard.

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fwissamyanis%2Fsentinel-all-in-one-defender%2Fmain%2Fazuredeploy-v3.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fwissamyanis%2Fsentinel-all-in-one-defender%2Fmain%2FcreateUiDefinition.json)

### Deploy the Windows Security Events DCR from the CLI

This module is self-contained and is the quickest way to test the new AMA/DCR piece:

```powershell
az login
az deployment group create `
  --resource-group "<rg-with-your-workspace>" `
  --template-file "LinkedTemplates/dataCollectionRules.json" `
  --parameters workspaceName="<your-workspace>" dataConnectorsKind='["SecurityEvents"]' securityEventSet="Common"
```

> The DCR creates the collection **rule**. To actually collect events, associate the DCR with machines that have the Azure Monitor Agent installed (via the Sentinel connector page or Azure Policy).

## Connecting the workspace to the Defender portal

There is no supported ARM/API to programmatically connect a workspace to the Defender portal — it is a portal action. Workspaces onboarded to Sentinel after **July 1, 2025** are, in many cases, connected automatically.

`Scripts/Connect-DefenderPortal.ps1` verifies the workspace is ready (workspace exists, Sentinel enabled, Defender XDR connector present) and prints the remaining portal step and required roles:

```powershell
./Scripts/Connect-DefenderPortal.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -WorkspaceName <workspace>
```

To onboard you need **Security Administrator** (Microsoft Entra ID) plus **Owner** (unconditional) at the subscription scope, or **User Access Administrator + Microsoft Sentinel Contributor**. See [Connect Microsoft Sentinel to the Defender portal](https://learn.microsoft.com/en-us/unified-secops/microsoft-sentinel-onboard).

## Repository layout

```
azuredeploy-v3.json          Main deployment template (entry point)
createUiDefinition.json      Portal wizard UI
DEFENDER-CHANGES.md          Details of the Defender-era changes
LinkedTemplates/             Workspace, settings, solutions, connectors, DCR, rules
Scripts/                     Connect-DefenderPortal.ps1, EnableRules.ps1
media/                       Logo and assets
```

## Credits

Based on the original [Sentinel All-in-One](https://github.com/javiersoriano/sentinel-all-in-one) by **Javier Soriano** and the Microsoft Sentinel community. This edition extends it with Microsoft Defender portal support.
