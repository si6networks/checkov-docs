# CKV_AWS_307: Ensure SageMaker Users should not have root access to SageMaker notebook instances
## Severity
**LOW** (score: 2.0/10)

This check verifies root access is disabled on SageMaker notebook instances; root access lets any notebook user escalate privileges on the underlying instance and access the instance's IAM role credentials and any co-located data.

## Summary
This check ensures an `aws_sagemaker_notebook_instance` resource explicitly sets `root_access = "Disabled"`, preventing users of the notebook from gaining root/administrator privileges on the underlying instance.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_sagemaker_notebook_instance`

## Why it matters
SageMaker notebook instances default to allowing root access, which lets any user with notebook access install arbitrary software, modify system configuration, bypass any endpoint/network restrictions configured at the OS level, disable logging or monitoring agents running on the instance, and potentially escalate the instance's effective privileges beyond what was intended by the platform team. Because notebook users are frequently data scientists working with sensitive training data and often have IAM roles attached to the instance with permissions to access S3 buckets, other AWS services, or internal data sources, unrestricted root access dramatically increases the risk that a compromised or malicious user session can pivot laterally, exfiltrate data via unmonitored channels, or persist unauthorized changes to the instance. Disabling root access enforces least privilege and reduces the notebook's attack surface to just the intended data science workflow, aligning with NIST 800-53 AC-6 (least privilege) and related access control families.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (Python check) with `missing_block_result=CheckResult.FAILED` explicitly set, meaning an absent attribute is treated as a failure (not silently passed). It inspects the `root_access` attribute:
- **PASS** if `root_access = "Disabled"`.
- **FAIL** if `root_access` is missing (default is `Enabled`) or explicitly set to `"Enabled"`.

## Non-compliant example
```hcl
resource "aws_sagemaker_notebook_instance" "example" {
  name          = "data-science-notebook"
  role_arn      = aws_iam_role.sagemaker.arn
  instance_type = "ml.t3.medium"
  # root_access not set -> defaults to Enabled, check FAILS
}
```

## Remediated example
```hcl
resource "aws_sagemaker_notebook_instance" "example" {
  name          = "data-science-notebook"
  role_arn      = aws_iam_role.sagemaker.arn
  instance_type = "ml.t3.medium"
  root_access   = "Disabled"   # remove root privileges from notebook users
}
```

## Remediation steps
1. Add `root_access = "Disabled"` to every `aws_sagemaker_notebook_instance` resource.
2. Test that any lifecycle-configuration scripts or custom kernels your team relies on do not depend on root-level operations (e.g., `sudo pip install`, apt package installs) — with root disabled, package installs typically must be done via `pip install --user`, conda environments, or baked into a custom lifecycle configuration/AMI ahead of time.
3. If a specific workflow genuinely requires elevated privileges, prefer running that workload in SageMaker Studio/Processing Jobs with a scoped, purpose-built container image instead of granting root on a persistent interactive notebook.
4. Communicate the change to data science teams in advance, since existing workflows relying on ad hoc root package installs will need to migrate to a supported alternative.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerNotebookRoot.py)
