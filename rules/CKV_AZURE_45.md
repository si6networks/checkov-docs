# CKV_AZURE_45: Ensure that no sensitive credentials are exposed in VM custom_data

## Severity
**HIGH** (score: 7.5/10)

Embedding passwords, keys, or tokens in VM custom_data (cloud-init/user data) exposes hardcoded credentials to anyone with instance metadata or template access, a direct and high-impact credential leakage path.

## Summary
This check scans the `custom_data` (cloud-init/provisioning script) field of an Azure Virtual Machine's OS profile for hardcoded secrets such as passwords, API keys, or tokens.

## Applicability
- **Terraform**: `azurerm_virtual_machine`
- **ARM templates**: `Microsoft.Compute/virtualMachines`
- **Bicep**: `Microsoft.Compute/virtualMachines` (via the underlying ARM/Terraform check logic)

## Why it matters
`custom_data` is typically a base64-encoded cloud-init script or bootstrap payload injected into a VM at provisioning time via the Azure instance metadata service. This data is not strongly protected — it can be readable by anyone with access to the ARM template/Terraform state (which itself is often stored in a shared backend), and on many platforms the rendered custom data remains queryable from within the VM's instance metadata endpoint even after boot, or persists in cloud-init logs (`/var/log/cloud-init-output.log`) accessible to any local user or process. Hardcoding credentials (database passwords, storage keys, API tokens) directly into this bootstrap script means the secret is committed to version control (if IaC is checked in), embedded in Terraform state, and potentially recoverable long after provisioning — turning what should be a one-time bootstrap value into a durable, widely-exposed credential leak.

## How Checkov evaluates this
Both the ARM and Terraform checks extract the custom data string (`properties.osProfile.customData` in ARM; `os_profile[0].custom_data` in Terraform) and run it through Checkov's shared secret-detection utility `string_has_secrets(custom_data, AZURE, GENERAL)`, which applies regex-based secret pattern matching (Azure-specific patterns plus generic credential patterns — e.g., connection strings, key=value assignments that look like passwords/API keys, common token formats). If any pattern matches, the check FAILS and Checkov also stores the offending string on the resource config (as `<check_id>_secret`) so it can be surfaced/redacted in reporting. If no secrets are detected in the custom data (or the field is absent), it PASSES.

## Non-compliant example
```hcl
resource "azurerm_virtual_machine" "example" {
  name                  = "example-vm"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  vm_size               = "Standard_DS1_v2"
  network_interface_ids = [azurerm_network_interface.example.id]

  os_profile {
    computer_name  = "examplevm"
    admin_username = "adminuser"
    admin_password = "P@ssw0rd123!"
    custom_data = base64encode(<<-EOF
      #!/bin/bash
      export DB_PASSWORD="SuperSecretPa55w0rd!"
      curl -H "Authorization: Bearer sk_live_51H8xxxx" https://internal-api/setup
    EOF
    )
  }
}
```

## Remediated example
```hcl
resource "azurerm_virtual_machine" "example" {
  name                  = "example-vm"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  vm_size               = "Standard_DS1_v2"
  network_interface_ids = [azurerm_network_interface.example.id]

  os_profile {
    computer_name  = "examplevm"
    admin_username = "adminuser"
    admin_password = "P@ssw0rd123!"
    custom_data = base64encode(<<-EOF
      #!/bin/bash
      # Fetch secrets at runtime from Key Vault via managed identity, no hardcoded creds
      az login --identity
      DB_PASSWORD=$(az keyvault secret show --name db-password --vault-name example-kv --query value -o tsv)
      curl -H "Authorization: Bearer $(az keyvault secret show --name api-token --vault-name example-kv --query value -o tsv)" https://internal-api/setup
    EOF
    )
  }
}
```

## Remediation steps
1. Remove any literal secrets, passwords, tokens, or connection strings from `custom_data` / cloud-init scripts.
2. Assign the VM a system- or user-assigned managed identity and grant it access to an Azure Key Vault via RBAC or access policy.
3. Modify the bootstrap script to fetch secrets at runtime from Key Vault (or Azure App Configuration) using the managed identity, rather than embedding them in the provisioning payload.
4. If a secret must be injected at boot for legacy reasons, use the Azure VM extension for Key Vault (or `azurerm_virtual_machine_extension` with a custom script that pulls from a secure store) instead of plaintext `custom_data`.
5. Rotate any credential that was previously hardcoded in `custom_data`, since it may already be present in Terraform state, source control history, or VM boot logs even after removal from the current configuration.

## References
- [Checkov check source (ARM)](https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/VMCredsInCustomData.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMCredsInCustomData.py)
- [Azure custom data / cloud-init documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/custom-data)
