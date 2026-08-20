# CKV_AWS_330: EFS access points should enforce a user identity
## Severity
**MEDIUM** (score: 5.0/10)

Failing to enforce a POSIX user identity on an EFS access point means files created through that access point default to root/broader permissions, weakening the per-application isolation the access point is meant to provide on shared storage.

## Summary
This check requires that EFS access points configure a `posix_user` block (specifically a `gid`), so that all NFS operations through the access point are performed under an enforced POSIX user/group identity rather than whatever identity the client's OS process happens to run as.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_efs_access_point`

## Why it matters
Without an enforced `posix_user`, EFS honors the UID/GID that the connecting client (e.g., a container process) presents at mount/operation time — meaning any process that can mount the access point can read/write files as whatever user it claims to be, including as `root` (UID 0) if the container runs privileged or the client isn't restricted. This breaks the file-level access control model that Unix permissions on the underlying files are supposed to provide, and it removes an important isolation boundary in multi-tenant or shared-storage scenarios (e.g., multiple ECS tasks or Lambda functions sharing one EFS access point). Enforcing a specific UID/GID at the access-point layer means the file system's permission checks are anchored to an identity that AWS itself controls and audits, independent of what the client claims.

## How Checkov evaluates this
The check (`EFSAccessUserIdentity.py`) is a `BaseResourceValueCheck`:
- It inspects the nested key `posix_user/[0]/gid`.
- If `posix_user.gid` is set to **any** value (`ANY_VALUE`), the check **PASSES**.
- If the `posix_user` block or its `gid` field is absent, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_efs_access_point" "bad_example" {
  file_system_id = aws_efs_file_system.shared.id

  root_directory {
    path = "/app-data"
  }
  # no posix_user block -> client-supplied UID/GID is used
}
```

## Remediated example
```hcl
resource "aws_efs_access_point" "good_example" {
  file_system_id = aws_efs_file_system.shared.id

  root_directory {
    path = "/app-data"
  }

  posix_user {
    uid = 1000
    gid = 1000
  }
}
```

## Remediation steps
1. Add a `posix_user` block specifying `uid` and `gid` values appropriate for the application (typically a dedicated non-root service account, never `0`).
2. Ensure the underlying directory (set via `root_directory.path`/`creation_info`) is owned by or otherwise permits that UID/GID so the application can actually read/write as expected.
3. Combine with CKV_AWS_329 (enforce non-root `root_directory.path`) for full access-point isolation.
4. `posix_user` requires replacement of the access point if changed after creation — plan the identity carefully up front, or expect to create a new access point and remount clients pointing at it.
5. Verify your mount helper / ECS task / Lambda EFS configuration actually uses this access point (not the raw file system) so the enforced identity takes effect.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EFSAccessUserIdentity.py)
- [AWS: Working with users, groups, and permissions using EFS access points](https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html)
