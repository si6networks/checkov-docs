# CKV_OCI_23: Ensure OCI Data Catalog is configured without overly permissive network access

## Severity
**HIGH** (score: 7.5/10)

A Data Catalog without attached private endpoints is reachable over the public network, risking exposure of sensitive metadata and cataloged data-source connection information to unauthorized actors.

## Summary
This check ensures that an OCI Data Catalog (`oci_datacatalog_catalog`) is attached to at least one private endpoint, restricting network access rather than being reachable over the public internet.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `oci_datacatalog_catalog`

## Why it matters
OCI Data Catalog stores metadata about your organization's data assets — schemas, table/column names, business glossaries, data lineage, and classification/sensitivity tags. This metadata itself is highly valuable reconnaissance information for an attacker: knowing where sensitive data lives, how it's structured, and how systems are connected significantly accelerates a targeted attack against the underlying data stores. Without a private endpoint attachment, the catalog's connection/service endpoints are reachable without being confined to your private network (VCN), increasing exposure to unauthorized access attempts, credential-stuffing against catalog APIs, or data harvesting by anyone who can reach the public endpoint. Attaching the catalog exclusively to a private endpoint within your VCN ensures only network paths you explicitly control (e.g., peered VCNs, on-prem via FastConnect/VPN) can reach it.

## How Checkov evaluates this
This is a custom `BaseResourceCheck` on `oci_datacatalog_catalog`. It inspects the `attached_catalog_private_endpoints` attribute:
- If the attribute is present and its list has at least one entry (`len(...) > 0`) → PASSED.
- If the attribute is present but empty → FAILED.
- If the attribute is absent entirely → FAILED.

## Non-compliant example
```hcl
resource "oci_datacatalog_catalog" "org_catalog" {
  compartment_id = var.compartment_id
  display_name   = "org-data-catalog"
  # No attached_catalog_private_endpoints - reachable via public endpoint
}
```

## Remediated example
```hcl
resource "oci_datacatalog_catalog_private_endpoint" "catalog_pe" {
  compartment_id = var.compartment_id
  display_name   = "catalog-private-endpoint"
  subnet_id      = var.private_subnet_id
  dns_zones      = [var.dns_zone]
}

resource "oci_datacatalog_catalog" "org_catalog" {
  compartment_id                     = var.compartment_id
  display_name                       = "org-data-catalog"
  attached_catalog_private_endpoints = [oci_datacatalog_catalog_private_endpoint.catalog_pe.id]
}
```

## Remediation steps
1. Create an `oci_datacatalog_catalog_private_endpoint` in a private subnet of your VCN.
2. Attach it to the catalog via the `attached_catalog_private_endpoints` list.
3. Update any client tooling (data catalog UI/API consumers) to reach the catalog only via the private endpoint's DNS/network path (VPN, FastConnect, or VCN peering as appropriate).
4. Attaching a private endpoint to an existing catalog is generally an in-place operation, but plan a maintenance window to update DNS/connectivity for consumers who previously used the public endpoint.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/oci/DataCatalogWithPublicAccess.py)
