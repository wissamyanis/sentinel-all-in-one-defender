# Sentinel Accelerated All-in-One

![Sentinel Accelerated All-in-One](./media/SentinelAcceleratedLogo.png)

> Personal copy of [Javier Soriano's Sentinel All-in-One](https://github.com/javiersoriano/sentinel-all-in-one), extended for the unified **Microsoft Defender portal**. All original authorship and credit belong to Javier Soriano.

This template speeds up standing up a Microsoft Sentinel environment (Log Analytics workspace + Sentinel + Content Hub solutions + data connectors + analytics rules), updated for the Defender-portal era.

## What is new in this edition

- Data connector API versions bumped to GA `2025-09-01`
- New connectors: **Microsoft Defender Threat Intelligence** and **Premium MDTI**
- "Microsoft 365 Defender" relabeled **Microsoft Defender XDR**
- **Windows Security Events via AMA** using a Data Collection Rule (All / Common / Minimal sets)
- `Scripts/Connect-DefenderPortal.ps1` to verify readiness and guide Defender portal onboarding
- Optional modern subscription-scope **AzureActivity** connector

Full details: see [DEFENDER-CHANGES.md](./DEFENDER-CHANGES.md).

## Deploy

> The Deploy to Azure button requires this repository to be **Public** (the Azure portal fetches the templates from raw.githubusercontent.com).

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fwissamyanis%2Fsentinel-all-in-one-defender%2Fmain%2Fazuredeploy-v3.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fwissamyanis%2Fsentinel-all-in-one-defender%2Fmain%2FcreateUiDefinition.json)

### Deploy from the CLI

```powershell
az deployment group create `
  --resource-group "<rg-with-your-workspace>" `
  --template-file "LinkedTemplates/dataCollectionRules.json" `
  --parameters workspaceName="<your-workspace>" dataConnectorsKind='["SecurityEvents"]' securityEventSet="Common"
```

## Repository layout

```
azuredeploy-v3.json          Main deployment template (entry point)
createUiDefinition.json      Portal wizard UI
DEFENDER-CHANGES.md          Details of the Defender-era changes
LinkedTemplates/             Workspace, settings, solutions, connectors, DCR, rules
Scripts/                     Connect-DefenderPortal.ps1, EnableRules.ps1
media/                       Logo and demo assets
```
