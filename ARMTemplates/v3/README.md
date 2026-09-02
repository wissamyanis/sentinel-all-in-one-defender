

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjaviersoriano%2Fsentinel-all-in-one%2Fmaster%2FARMTemplates%2Fv3%2Fazuredeploy-v3.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fjaviersoriano%2Fsentinel-all-in-one%2Fmaster%2FARMTemplates%2Fv3%2FcreateUiDefinition.json)

## Defender portal / unified SecOps updates

Microsoft Sentinel now runs in the unified Microsoft Defender portal (security.microsoft.com). Sentinel is still deployed on Azure (a Log Analytics workspace with Sentinel enabled) — the Defender portal is the operational front end. This v3 adds the connector and collection changes that come with that move.

### Data connectors

Connector API versions are updated to the GA `2025-09-01` API. New connector options in the deployment UI:

| Connector | `kind` | Notes |
| --- | --- | --- |
| Microsoft Defender XDR | `MicrosoftThreatProtection` | Central connector for the unified portal. Streams incidents/alerts. (Previously labeled "Microsoft 365 Defender".) |
| Microsoft Defender Threat Intelligence | `MicrosoftThreatIntelligence` | Modern TI connector — ingests the Microsoft emerging threat feed. Replaces the legacy `ThreatIntelligence` connector for new deployments. |
| Premium Microsoft Defender Threat Intelligence | `PremiumMicrosoftDefenderForThreatIntelligence` | Premium MDTI indicator feed. Requires the MDTI premium license. |
| Threat Intelligence Platforms (legacy) | `ThreatIntelligence` | Kept for backward compatibility; prefer the connectors above. |

### Windows Security Events via AMA (Data Collection Rule)

The legacy Log Analytics agent (MMA/OMS) is retired. Windows Security Events are now collected with the **Azure Monitor Agent (AMA)** driven by a **Data Collection Rule (DCR)**.

- Select **"Security Events via AMA (Windows)"** in the Data connectors tab.
- Choose an event set: **All**, **Common**, or **Minimal**. The exact event IDs match the Microsoft [Windows security event sets](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference) reference, split across the Security and AppLocker channels.
- Template: `LinkedTemplates/dataCollectionRules.json` (creates a DCR named `DCR-WindowsSecurityEvents-<hash>` targeting the workspace).

> **DCR association is a separate step.** This creates the DCR; you must associate it with your machines (which must have AMA installed) via the Sentinel connector page or Azure Policy. The deployment cannot associate machines it does not know about at deploy time.

### Connecting the workspace to the Defender portal

There is no supported ARM/API to programmatically connect a workspace to the Defender portal — it is a portal action. Workspaces onboarded to Sentinel after **July 1, 2025** are, in many cases, connected automatically.

`Scripts/Connect-DefenderPortal.ps1` verifies the workspace is ready (workspace exists, Sentinel enabled, Defender XDR connector present) and prints the remaining portal step and the required roles.

```powershell
./Scripts/Connect-DefenderPortal.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -WorkspaceName <workspace>
```

To onboard you need **Security Administrator** (Microsoft Entra ID) plus **Owner** (unconditional) at the subscription scope, or **User Access Administrator + Microsoft Sentinel Contributor**. See [Connect Microsoft Sentinel to the Defender portal](https://learn.microsoft.com/en-us/unified-secops/microsoft-sentinel-onboard).

### Optional / future work: modern AzureActivity connector

The default AzureActivity connector in `dataConnectors.json` still uses the legacy `Microsoft.OperationalInsights/workspaces/dataSources` (kind `AzureActivityLog`) resource. It works, but Microsoft's current guidance is to stream the Activity Log via a **subscription-scope diagnostic setting**.

`LinkedTemplates/dataConnectors-AzureActivity-modern.json` implements that modern approach (validated with ARM-TTK, 32/32). It is **not wired into the main flow** because it is a subscription-scope deployment and should be validated in a sandbox first. To adopt it, invoke it from the parent as a subscription-scoped nested deployment (no `resourceGroup`), passing the workspace resource ID, and remove the AzureActivity resource from `dataConnectors.json`.


