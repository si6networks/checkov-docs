# CKV_AZURE_243: Ensure Azure Machine learning workspace is configured with private endpoint

## Severity
**MEDIUM** (score: 5.0/10)

An Azure Machine Learning workspace without a private endpoint communicates over the public network, broadening the attack surface for a service that handles sensitive training data and models.

## Summary
This check ensures an Azure Machine Learning workspace's managed virtual network has at least one outbound rule of type `PrivateEndpoint`, so that outbound traffic from the workspace's managed compute reaches dependent services privately instead of over the public internet.

## Applicability
- **ARM/Bicep**: `Microsoft.MachineLearningServices/workspaces` — inspects `properties.managedNetwork.outboundRules` for any rule with `type == "PrivateEndpoint"`.

## Why it matters
Azure ML workspaces with a managed virtual network route outbound traffic from managed compute (training clusters, compute instances, managed online endpoints) through configurable outbound rules. If none of those rules are private-endpoint-based, traffic to dependent services (storage accounts holding training data, container registries, Key Vault) can traverse the public internet path, which both increases the exposed attack surface (public endpoints of dependent services must remain reachable, widening what needs to be locked down elsewhere) and reduces the ability to enforce that sensitive training data/model traffic never leaves Microsoft's private backbone. This matters for the same reasons private endpoints matter generally: it prevents traffic interception on the public path, lets you rely on network-layer controls in addition to just identity/RBAC, and is often mandated by policies requiring "all traffic to/from a resource must be private" for workloads handling sensitive training data or proprietary models.

## How Checkov evaluates this
`BaseResourceCheck` on `Microsoft.MachineLearningServices/workspaces`. It navigates `properties.managedNetwork.outboundRules` (a dict of named rules). It PASSES as soon as it finds any rule (excluding internal `START_LINE`/`END_LINE` bookkeeping keys Checkov injects) whose `type` field equals `"PrivateEndpoint"`. If `managedNetwork`, `outboundRules`, or a qualifying rule are missing, it FAILS.

## Non-compliant example
```bicep
resource mlWorkspace 'Microsoft.MachineLearningServices/workspaces@2023-04-01' = {
  name: 'example-mlworkspace'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    friendlyName: 'example-mlworkspace'
    storageAccount: storageAccount.id
    keyVault: keyVault.id
    applicationInsights: appInsights.id
    // no managedNetwork / outboundRules configured -> FAILS
  }
}
```

## Remediated example
```bicep
resource mlWorkspace 'Microsoft.MachineLearningServices/workspaces@2023-04-01' = {
  name: 'example-mlworkspace'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    friendlyName: 'example-mlworkspace'
    storageAccount: storageAccount.id
    keyVault: keyVault.id
    applicationInsights: appInsights.id
    managedNetwork: {
      isolationMode: 'AllowOnlyApprovedOutbound'
      outboundRules: {
        storagePe: {
          type: 'PrivateEndpoint'          // <-- private endpoint outbound rule, PASSES
          destination: {
            serviceResourceId: storageAccount.id
            subresourceTarget: 'blob'
            sparkEnabled: true
          }
        }
      }
    }
  }
}
```

## Remediation steps
1. Configure the workspace's `managedNetwork.isolationMode` to `AllowOnlyApprovedOutbound` (or `AllowInternetOutbound`, though the stricter mode is recommended) so outbound rules are enforced.
2. Add at least one `outboundRules` entry of `type: "PrivateEndpoint"` targeting each dependent resource (storage account, Key Vault, container registry) that the workspace's managed compute needs to reach.
3. Ensure the target resources (storage, Key Vault, ACR) themselves have private endpoints provisioned and, ideally, public network access disabled to fully close the public path.
4. Managed virtual network provisioning for Azure ML workspaces can take significant time on first apply and may not be modifiable in-place after creation in all scenarios — validate in a non-production workspace first.
5. Confirm any compute instances/clusters and managed online endpoints in the workspace are compatible with the managed VNet's isolation mode — some legacy compute configurations may require adjustment.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AzureMLWorkspacePrivateEndpoint.py
- Azure docs: https://learn.microsoft.com/en-us/azure/machine-learning/how-to-managed-network
