# CKV_AZURE_235: Ensure that Azure container environment variables are configured with secure values only

## Severity
**CRITICAL** (score: 9.0/10)

Plaintext environment variables on Azure Container Instances can hold secrets (API keys, connection strings, passwords) in the container spec, exposing credentials to anyone with read access to the resource definition or runtime metadata.

## Summary
This check flags Azure Container Instance (ACI) container groups whose containers use the plain `environment_variables` block instead of Azure's `secure_environment_variables` mechanism, on the theory that sensitive values should never be passed as plaintext environment variables.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `azurerm_container_group` resources — inspects the `container` and `init_container` blocks for an `environment_variables` key.

## Why it matters
Environment variables set via the ordinary (non-secure) mechanism on Azure Container Instances are visible in the container's properties via the Azure API/CLI/Portal (e.g., `az container show`) and can be visible to anyone with read access to the container group resource, not just to the running process. If a secret, API key, or connection string is placed in a plain environment variable, it is effectively exposed to any principal with read/list permissions on the resource group — a much broader blast radius than intended, and it also tends to end up captured in deployment logs, Terraform state, or CI/CD output. Azure Container Instances provide a dedicated `secure_environment_variables` (or `secure_value` in ARM) mechanism specifically so secret values are hidden from the control-plane read APIs.

## How Checkov evaluates this
`BaseResourceCheck` on `azurerm_container_group`. It iterates over each `container` and `init_container` block (via `itertools.chain`). For the first container/init_container in that combined iterable, if the block has an `environment_variables` key present at all, the check returns `FAILED`; otherwise it returns `PASSED`. Note the implementation returns immediately after evaluating only the first item in the chain — it does not continue checking subsequent containers.

In practice: any container group that uses `environment_variables` (the plaintext form) on its first container fails; container groups that use only `secure_environment_variables` (or no environment variables at all) pass.

## Non-compliant example
```hcl
resource "azurerm_container_group" "example" {
  name                = "example-cg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  os_type             = "Linux"

  container {
    name   = "app"
    image  = "myregistry.azurecr.io/app:latest"
    cpu    = "0.5"
    memory = "1.5"

    environment_variables = {
      DB_PASSWORD = "SuperSecret123!"   # plaintext, visible via API -> FAILS
    }
  }
}
```

## Remediated example
```hcl
resource "azurerm_container_group" "example" {
  name                = "example-cg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  os_type             = "Linux"

  container {
    name   = "app"
    image  = "myregistry.azurecr.io/app:latest"
    cpu    = "0.5"
    memory = "1.5"

    secure_environment_variables = {
      DB_PASSWORD = var.db_password   # hidden from read APIs, PASSES
    }
  }
}
```

## Remediation steps
1. Move any secret, credential, token, or connection-string value out of `environment_variables` and into `secure_environment_variables`.
2. Keep genuinely non-sensitive configuration (feature flags, region names, non-secret URLs) in ordinary `environment_variables` if desired — Checkov's implementation here only checks the first container/init_container in the group, so verify manually across all containers in a multi-container group.
3. Source the secret values themselves from a secure origin (Azure Key Vault via Terraform data source, a secrets manager, or a CI/CD secret store) rather than hardcoding them in `.tf` files.
4. Consider whether ACI is the right compute choice for secret-heavy workloads at all — for more sensitive scenarios, prefer Key Vault references injected via managed identity at runtime rather than any environment-variable mechanism.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureContainerInstanceEnvVarSecureValueType.py
- Azure docs: https://learn.microsoft.com/en-us/azure/container-instances/container-instances-environment-variables#secure-values
