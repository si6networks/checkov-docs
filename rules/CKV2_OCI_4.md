# CKV2_OCI_4: Ensure File Storage File System access is restricted to root users

## Severity
**MEDIUM** (score: 5.0/10)

Without proper root-squash mapping, any NFS client presenting root credentials is trusted as root on the file system, allowing full read/write/ownership access to every file in a potentially multi-tenant export.

## Summary
This check ensures OCI File Storage NFS exports (`oci_file_storage_export`) apply an `identity_squash` setting of `ROOT` combined with `anonymous_uid`/`anonymous_gid` both set to `65534` (the conventional `nobody`/`nogroup` IDs), so that clients presenting root credentials over NFS are mapped down to an unprivileged identity rather than being trusted as root.

## Applicability
**Checkov framework(s):** `terraform`

Terraform. Applies to the `oci_file_storage_export` resource, specifically its `export_options[].identity_squash`, `export_options[].anonymous_uid`, and `export_options[].anonymous_gid` attributes.

## Why it matters
NFS has historically trusted the UID/GID asserted by the connecting client rather than performing strong server-side authentication of the calling user. Without root-squashing, any client that can mount the export and present UID 0 (root) is treated as root on the file system, giving it full read/write/ownership-change access to every file in the export, including files owned by other users. This is especially dangerous in shared/multi-tenant environments (shared OKE clusters, multiple VMs mounting the same file system) because a single compromised or misconfigured client with root access can compromise or corrupt data belonging to every other consumer of that export. Setting `identity_squash = "ROOT"` with anonymous UID/GID mapped to `65534` ("nobody") ensures a client presenting root credentials is downgraded to a non-privileged, non-owning identity on the server side, containing the blast radius of a compromised or rogue NFS client.

## How Checkov evaluates this
Graph-based JSON policy (`OCI_NFSaccessRestrictedToRootUsers.json`) using JSONPath conditions on `export_options`. It passes if EITHER:
1. No entry in `export_options` has `identity_squash` matching (case-insensitive) `ROOT` (i.e., the export has no root-squash configuration at all — treated as out of scope for this specific check), OR
2. There EXISTS an entry in `export_options` where `identity_squash` matches `ROOT` **and** `anonymous_gid == 65534` **and** `anonymous_uid == 65534` (properly configured root-squash with standard nobody/nogroup IDs).
It fails when an export has an `identity_squash` entry present that is set to `ROOT` but the `anonymous_uid`/`anonymous_gid` are NOT both `65534` (i.e., root-squash is attempted but misconfigured with non-standard/incorrect anonymous identity values).

## Non-compliant example
```hcl
resource "oci_file_storage_export" "app_export" {
  export_set_id  = oci_file_storage_export_set.app_export_set.id
  file_system_id = oci_file_storage_file_system.app_fs.id
  path           = "/app-data"

  export_options {
    source                         = "10.0.0.0/24"
    access                         = "READ_WRITE"
    identity_squash                = "ROOT"
    anonymous_uid                  = 0        # incorrect - still maps root to uid 0
    anonymous_gid                  = 0
    require_privileged_source_port = false
  }
}
```

## Remediated example
```hcl
resource "oci_file_storage_export" "app_export" {
  export_set_id  = oci_file_storage_export_set.app_export_set.id
  file_system_id = oci_file_storage_file_system.app_fs.id
  path           = "/app-data"

  export_options {
    source                         = "10.0.0.0/24"
    access                         = "READ_WRITE"
    identity_squash                = "ROOT"
    anonymous_uid                  = 65534    # nobody
    anonymous_gid                  = 65534    # nogroup
    require_privileged_source_port = false
  }
}
```

## Remediation steps
1. For every `oci_file_storage_export` resource, review the `export_options` blocks.
2. Where `identity_squash = "ROOT"` is set, ensure `anonymous_uid` and `anonymous_gid` are both `65534` (the standard `nobody`/`nogroup` values expected by most Unix systems).
3. If `identity_squash` is absent entirely, consider explicitly adding `identity_squash = "ROOT"` with the correct anonymous IDs rather than leaving root-squash unset, especially for exports shared across multiple clients/tenants.
4. Also consider `require_privileged_source_port = true` and scoping `source` to specific trusted CIDRs for additional defense-in-depth on NFS exports.
5. Test the change in a non-production export first — altering `identity_squash`/anonymous ID mappings can change effective file permissions for existing files owned by uid/gid 0 on the export.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/oci/OCI_NFSaccessRestrictedToRootUsers.json
