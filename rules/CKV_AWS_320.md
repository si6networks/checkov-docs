# CKV_AWS_320: Ensure Redshift clusters do not use the default database name

## Severity
**MEDIUM** (score: 5.0/10)

Using a non-default Redshift database name is a security-through-obscurity hardening step with negligible direct impact on exploitability.

## Summary
This check ensures Amazon Redshift clusters explicitly set a custom database name rather than relying on the implicit default.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_redshift_cluster`

## Why it matters
Redshift's default initial database name is `dev` when none is specified. Predictable, default resource names (database names, default admin usernames, default ports) make automated reconnaissance and credential-stuffing/brute-force attacks measurably easier: an attacker who gains any level of network or credential access no longer needs to guess or enumerate the database name — one of the several pieces of information otherwise needed to build a working connection string is already known. This is the same class of risk addressed by avoiding default usernames (e.g., not using `admin`/`postgres`) — reducing the attack surface by eliminating well-known defaults, in line with baseline configuration management practices (NIST 800-53 CM-2).

## How Checkov evaluates this
A `BaseResourceValueCheck` with `missing_block_result = CheckResult.FAILED`, inspecting the `database_name` attribute:
- **FAIL** if `database_name` is not set at all (missing block is explicitly treated as a failure here, unlike many other value checks).
- **PASS** if `database_name` is set to any value (`ANY_VALUE` — the check does not specifically verify the value differs from `"dev"`; it only requires the attribute be explicitly specified rather than left to default).

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "example" {
  cluster_identifier = "example-cluster"
  node_type           = "dc2.large"
  cluster_type        = "single-node"
  master_username     = "admin"
  master_password     = var.redshift_password
  # database_name not set -> defaults to "dev"
}
```

## Remediated example
```hcl
resource "aws_redshift_cluster" "example" {
  cluster_identifier = "example-cluster"
  node_type           = "dc2.large"
  cluster_type        = "single-node"
  master_username     = "admin"
  master_password     = var.redshift_password
  database_name       = "app_analytics_db"   # explicit, non-default database name
}
```

## Remediation steps
1. Add an explicit `database_name` attribute to every `aws_redshift_cluster` resource, choosing a name specific to the application/workload rather than the default `dev`.
2. Changing `database_name` on an **existing** cluster requires replacement (Redshift does not support renaming the initial database in place) — plan for data migration/backup and restore, or apply this only to newly created clusters.
3. Combine with strong, rotated `master_password` values (stored in Secrets Manager) and a non-default `master_username` for defense in depth.
4. Restrict network access via security groups/VPC configuration regardless of naming, since obscurity alone is not a substitute for access control.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftClusterDatabaseName.py
- AWS docs: https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-console.html
