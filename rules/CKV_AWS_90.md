# CKV_AWS_90: Ensure DocumentDB TLS is not disabled

## Severity
**MEDIUM** (score: 5.0/10)

Disabling TLS on DocumentDB connections allows database traffic, including credentials and query data, to be transmitted in plaintext and intercepted or tampered with in transit.

## Summary
This check fails when an Amazon DocumentDB cluster parameter group explicitly sets the `tls` parameter to `disabled`, which turns off in-transit encryption for connections to the cluster.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_docdb_cluster_parameter_group` resource — inspects `parameter` blocks for a `name = "tls"` entry with `value = "disabled"`.
- **CloudFormation**: `AWS::DocDB::DBClusterParameterGroup` resource — inspects `Properties/Parameters/tls`.

## Why it matters
DocumentDB (MongoDB-compatible) is frequently used for application data that includes user records, session data, and other sensitive documents. TLS protects data in transit between application clients and the cluster; disabling it means credentials, queries, and query results traverse the network in plaintext. On a shared network segment, a misconfigured VPC, or via a compromised intermediate host, this exposes data to passive eavesdropping and makes on-path tampering (query/response manipulation) possible. DocumentDB requires the `tls` parameter to be explicitly enabled by default, so this check specifically flags configurations where someone has deliberately turned it off — a change that is rarely justified outside of very narrow legacy-compatibility scenarios.

## How Checkov evaluates this
- **Terraform**: Iterates the `parameter` blocks of the cluster parameter group. If any block has `name == "tls"` and `value == "disabled"` → **FAILED**. Otherwise → **PASSED** (including when no `tls` parameter is set at all, since the DocumentDB default is `enabled`).
- **CloudFormation**: `BaseResourceNegativeValueCheck` inspects `Properties/Parameters/tls`; the forbidden value is `"disabled"`.

## Non-compliant example
```hcl
resource "aws_docdb_cluster_parameter_group" "example" {
  family = "docdb4.0"
  name   = "docdb-cluster-pg"

  parameter {
    name  = "tls"
    value = "disabled"
  }
}
```

## Remediated example
```hcl
resource "aws_docdb_cluster_parameter_group" "example" {
  family = "docdb4.0"
  name   = "docdb-cluster-pg"

  parameter {
    name  = "tls"
    value = "enabled"   # or simply omit the tls parameter to keep the default
  }
}
```

## Remediation steps
1. Remove the `tls = "disabled"` parameter, or explicitly set it to `"enabled"`.
2. Update application connection strings to use `tls=true` / `ssl=true` and trust the Amazon RDS/DocumentDB CA bundle.
3. Applying a new parameter group to a running cluster requires a reboot of cluster instances to take effect — plan for a maintenance window.
4. Confirm client drivers support and use TLS 1.2+ before/after the change to avoid connectivity failures.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DocDBTLS.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DocDBTLS.py
- AWS docs: https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html
