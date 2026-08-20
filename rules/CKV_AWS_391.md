# CKV_AWS_391: Avoid AWS Redshift cluster with commonly used master username and public access setting enabled
## Severity
**CRITICAL** (score: 9.0/10)

Combining a commonly-used, guessable Redshift master username with public accessibility creates a direct, low-effort path for an external attacker to reach and brute-force a production data warehouse.

## Summary
This check flags Redshift clusters that combine a commonly-guessed master username (`awsuser`, `administrator`, or `admin`) with public accessibility, since the combination makes credential-guessing/brute-force attacks against an internet-reachable database trivially easier.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_redshift_cluster`

## Why it matters
Redshift's default master username is `awsuser`, and `admin`/`administrator` are also extremely common choices. When a cluster uses one of these predictable usernames AND is reachable from the public internet (`publicly_accessible = true`), an attacker only needs to compromise or brute-force the password half of the credential pair — the username is already known. This significantly narrows the attack surface for credential-stuffing and brute-force attacks, and increases the blast radius if the master password is ever leaked, weak, or reused. A publicly accessible data warehouse with a guessable admin username is a well-known pattern behind real-world data breaches.

## How Checkov evaluates this
This is a Python `BaseResourceCheck` against `aws_redshift_cluster`. The logic:
1. If `master_username` is set and its value is one of `awsuser`, `administrator`, or `admin` (case-sensitive, exact match):
   - If `publicly_accessible = true` → **FAIL**.
   - If `publicly_accessible` is not set at all → **FAIL** (the check treats the absence of the attribute as unsafe/undetermined, since Terraform/AWS default for `publicly_accessible` can vary or the plan may not make it explicit).
2. If `master_username` is not one of the common values, or `publicly_accessible` is explicitly `false`, the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "example" {
  cluster_identifier = "example-cluster"
  database_name      = "analytics"
  master_username    = "awsuser"
  master_password    = var.redshift_password
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  publicly_accessible = true
}
```

## Remediated example
```hcl
resource "aws_redshift_cluster" "example" {
  cluster_identifier = "example-cluster"
  database_name      = "analytics"
  master_username    = "rs_admin_7f2c"   # non-default, unpredictable username
  master_password    = var.redshift_password
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  publicly_accessible = false            # only reachable from within the VPC
}
```

## Remediation steps
1. Set `publicly_accessible = false` unless there is a documented business need for direct internet access to the cluster; prefer VPN/bastion/PrivateLink access instead.
2. If public accessibility genuinely is required, change `master_username` away from `awsuser`, `admin`, or `administrator` to a unique, non-guessable value.
3. Rotate the master password and enforce strong password policy/secrets management (e.g., Secrets Manager rotation) regardless.
4. Note that changing `master_username` on an existing cluster requires resource replacement (Redshift does not support renaming the master user in place), so plan for a maintenance window or blue/green cutover.
5. Restrict inbound access further with security groups even if `publicly_accessible` must remain `true`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftClusterWithCommonUsernameAndPublicAccess.py)
- [AWS Redshift cluster access documentation](https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html)
