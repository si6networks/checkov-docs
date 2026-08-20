# CKV_AWS_205: Ensure to Limit AMI launch Permissions
## Severity
**LOW** (score: 2.0/10)

Sharing AMI launch permissions with other accounts extends access to the full disk image -- including any embedded secrets, keys, or proprietary code -- well beyond the owning account's control boundary.

## Summary
Flags any use of the `aws_ami_launch_permission` resource, since granting launch permissions on an AMI to another account (or the public) widens who can create instances from your custom image.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_ami_launch_permission` — this check unconditionally fails whenever this resource type is present, regardless of the specific account ID/group being granted.

## Why it matters
An AMI launch permission determines which AWS accounts (or the general public, via the `all` group) are allowed to launch EC2 instances from your AMI. Because a custom AMI typically bakes in your organization's software, configuration, and sometimes residual secrets or internal hostnames from the build process, granting launch permissions to other accounts means:
- Those accounts can launch instances from your AMI and potentially extract sensitive baked-in data (config files, cached credentials, internal certificates) by inspecting the resulting instance's filesystem.
- If launch permissions are ever granted to the special "all" group (public), literally any AWS account worldwide can launch and inspect your AMI, turning an internal golden image into a public disclosure vector.
- Even scoped cross-account sharing widens your security boundary in ways that are easy to forget about over time (stale grants to decommissioned accounts, contractor accounts, etc.), since launch permissions don't expire and are rarely audited.

Because this resource's very purpose is to broaden who can use an AMI, Checkov flags its existence unconditionally so that any use is deliberately reviewed rather than silently accepted.

## How Checkov evaluates this
`AMILaunchIsShared` is a `BaseResourceCheck` whose `scan_resource_conf()` unconditionally returns `CheckResult.FAILED` whenever an `aws_ami_launch_permission` resource block exists, regardless of its configuration (target account, group, organization ARN, etc.):

```python
def scan_resource_conf(self, conf):
    return CheckResult.FAILED
```

## Non-compliant example
```hcl
resource "aws_ami_launch_permission" "share_with_partner" {
  image_id   = aws_ami.custom_image.id
  account_id = "123456789012"   # FAILS CKV_AWS_205 - any use of this resource fails
}
```

## Remediated example
```hcl
# Option 1: remove AMI sharing entirely and keep the AMI private to this account.

# Option 2: if sharing is a deliberate, reviewed business requirement,
# suppress the finding with an explicit justification comment rather than
# silently failing the scan, and restrict access as tightly as possible
# (specific account IDs only, never the "all" group; combine with a
# resource-based KMS key policy on the backing encrypted snapshot so the
# recipient account must also be explicitly granted key access).

resource "aws_ami_launch_permission" "share_with_partner" { #checkov:skip=CKV_AWS_205:Approved cross-account sharing for partner integration, see JIRA-1234
  image_id   = aws_ami.custom_image.id
  account_id = "123456789012"
}
```

## Remediation steps
1. Default to not sharing AMIs at all — keep them private to the account that built them.
2. If cross-account sharing is a genuine business requirement, restrict `account_id` to specific, actively-used account IDs only — never grant the `all`/public group.
3. Ensure the AMI's backing EBS snapshots are encrypted with a customer-managed KMS key, and explicitly grant the target account's IAM principals key policy permissions — this way, even a launch permission grant is useless to the recipient without corresponding key access, providing defense in depth.
4. Periodically audit and revoke stale `aws_ami_launch_permission` grants for accounts that no longer need access (e.g., decommissioned partners/environments).
5. If the finding is a deliberate, approved exception, suppress it explicitly with a `checkov:skip` comment referencing the approval/ticket, rather than leaving an unexplained failing scan result.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AMILaunchIsShared.py
- AWS docs: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html
