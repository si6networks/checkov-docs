# CKV_AWS_329: EFS access points should enforce a root directory
## Severity
**HIGH** (score: 7.5/10)

An EFS access point without an enforced root directory lets clients traverse into the full file system rather than a scoped subtree, weakening tenant isolation on shared storage even though it typically requires an additional access path to exploit.

## Summary
This check requires that EFS access points configure `root_directory.path` to a value other than `/` (the filesystem root), scoping the access point to a specific subdirectory instead of the entire file system.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_efs_access_point`

## Why it matters
An EFS access point is meant to provide application-specific entry points into a shared file system, enforcing a particular operating system user/group identity and a specific directory path. If the root directory is left as `/` (or unset, which defaults to root), the access point grants the mounting client visibility into and access to the entire file system — including data belonging to other applications or tenants that share the same EFS volume via other access points. This defeats the purpose of using access points for isolation and violates least-privilege: a compromised container or instance using this access point could read or tamper with files well outside its own application's namespace.

## How Checkov evaluates this
The check (`EFSAccessPointRoot.py`) extends `BaseResourceNegativeValueCheck`:
- It inspects the nested key `root_directory/[0]/path`.
- The forbidden value is `"/"` — if `root_directory.path` equals `/`, the check **FAILS**.
- If the `root_directory` block or `path` attribute is missing entirely, `missing_attribute_result=CheckResult.FAILED` also causes a **FAIL** (an access point with no configured root directory defaults to the file system root, which is the same risk).
- Any other explicit subdirectory path **PASSES**.

## Non-compliant example
```hcl
resource "aws_efs_access_point" "bad_example" {
  file_system_id = aws_efs_file_system.shared.id

  root_directory {
    path = "/"
  }
}
```

## Remediated example
```hcl
resource "aws_efs_access_point" "good_example" {
  file_system_id = aws_efs_file_system.shared.id

  root_directory {
    path = "/app-data"

    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "0755"
    }
  }
}
```

## Remediation steps
1. Set `root_directory.path` to an application-specific subdirectory (e.g., `/app-data`), never `/`.
2. Add a `creation_info` block so the directory is auto-created with the correct owner UID/GID and permissions if it doesn't already exist.
3. Pair this with `posix_user` (see CKV_AWS_330) to also enforce a specific POSIX identity for NFS operations through this access point.
4. If multiple applications share one EFS file system, give each its own access point scoped to its own subdirectory — this is the intended multi-tenant isolation pattern for EFS.
5. Changing `root_directory` on an existing access point requires replacement (it's an immutable attribute at the API level) — plan for a new access point and remount rather than an in-place update.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EFSAccessPointRoot.py)
- [AWS: Working with Amazon EFS access points](https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html)
