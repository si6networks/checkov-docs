# CKV_AZURE_103: Ensure that Azure Data Factory uses Git repository for source control
## Severity
**LOW** (score: 2.0/10)

Not using a Git repository for Data Factory source control is a change-management and traceability best practice with little direct exploitability on its own.

## Summary
This check ensures that an Azure Data Factory instance is configured with a Git (GitHub or Azure DevOps/VSTS) repository for source control of its pipelines, datasets, and linked services, rather than relying only on the "live" data factory mode.

## Applicability
- **Terraform**: `azurerm_data_factory` (inspects `github_configuration[0].repository_name` and `vsts_configuration[0].repository_name`)
- **ARM/Bicep**: `Microsoft.DataFactory/factories` (inspects `properties/repoConfiguration/type`)

## Why it matters
Data Factory pipelines often encode business-critical ETL logic, credentials/linked-service references, and data-movement configuration. Without source control, changes made directly in the "live mode" data factory (via the UX or ARM/API) are not versioned, cannot be code-reviewed, and leave no audit trail of who changed what pipeline logic and when. This creates real operational risk: a bad change (or a malicious insider change) can silently break or redirect data pipelines with no easy way to diff against a known-good state or roll back. Git integration enforces a change-management workflow (branches, pull requests, approvals) and gives you a durable history for incident investigation and compliance audits (e.g., SOX change-control requirements around data pipelines that feed financial reporting).

## How Checkov evaluates this
- **Terraform**: checks for either a `github_configuration` block with a non-empty `repository_name`, or a `vsts_configuration` block with a non-empty `repository_name`. If either is present, the check **PASSES**; if neither is configured, it **FAILS**.
- **ARM**: looks at `properties/repoConfiguration`. If this block is missing entirely, the check **FAILS**. If present and its `type` field is set (non-null), the check **PASSES**. If the block is present but ambiguous (no clear `type`), the result is `UNKNOWN`.

## Non-compliant example
```hcl
resource "azurerm_data_factory" "bad_example" {
  name                = "bad-datafactory"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  # No github_configuration or vsts_configuration block -> "live mode" only
}
```

## Remediated example
```hcl
resource "azurerm_data_factory" "good_example" {
  name                = "good-datafactory"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  # Fix: integrate with a Git repository for source control
  github_configuration {
    account_name    = "my-org"
    branch_name     = "main"
    git_url         = "https://github.com"
    repository_name = "data-factory-pipelines"
    root_folder     = "/"
  }
}
```

## Remediation steps
1. Add a `github_configuration` block (for GitHub) or `vsts_configuration` block (for Azure DevOps/VSTS) to the `azurerm_data_factory` resource, specifying the account/organization, repository name, branch, and root folder.
2. In ARM/Bicep, set `properties.repoConfiguration` with the appropriate `type` (`FactoryGitHubConfiguration` or `FactoryVSTSConfiguration`) and connection details.
3. Ensure the Data Factory's collaboration branch is protected (require pull-request review) in the Git provider itself — Checkov only verifies that Git integration exists, not that branch protection is configured.
4. If the factory was created in "live mode" already, connecting it to Git via the Author UX/API is a one-time, low-risk operation that imports existing pipelines into the repo.
5. Coordinate with the team owning the target repo/org since GitHub/DevOps app permissions or PATs may need to be provisioned first.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/DataFactoryUsesGitRepository.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataFactoryUsesGitRepository.py)
- [Azure docs: Source control in Azure Data Factory](https://learn.microsoft.com/en-us/azure/data-factory/source-control)
