# CKV_AWS_105: Ensure Redshift uses SSL
## Severity
**LOW** (score: 2.0/10)

Not requiring SSL (require_ssl) on Redshift connections allows client-to-cluster traffic, including query results and credentials, to be transmitted unencrypted and susceptible to interception.

## Summary
This check ensures that Amazon Redshift cluster parameter groups enforce SSL (`require_ssl = true`) for client connections to the data warehouse.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **CloudFormation**: `AWS::Redshift::ClusterParameterGroup` resources.
- **Terraform**: `aws_redshift_parameter_group` resources.

Specifically the `require_ssl` parameter within the parameter group's `Parameters`/`parameter` block.

## Why it matters
Redshift clusters commonly hold large volumes of consolidated analytical/warehouse data — often the most sensitive aggregated data in an organization (customer records, financial data, PII). Without `require_ssl` enforced, client connections (from BI tools, ETL jobs, application query layers) can fall back to unencrypted connections, exposing query results, credentials sent during connection setup, and query text in plaintext to anyone able to observe network traffic — for example on a shared VPC, a misconfigured peering connection, or a compromised intermediate host. Enforcing SSL at the parameter-group level ensures the requirement is applied consistently regardless of individual client driver configuration, closing a gap where a single misconfigured client could otherwise connect in the clear.

## How Checkov evaluates this
- **CloudFormation** (Python check): iterates `Properties.Parameters`; if any parameter's `ParameterName` is `require_ssl` and its `ParameterValue` (after normalizing boolean to lowercase string) is `"true"`, the check **PASSES**; otherwise **FAILS**.
- **Terraform**: if the resource has no `parameter` block at all, **FAILS** immediately. Otherwise, iterates `parameter` entries; if one has `name == "require_ssl"` and `value == [True]`, **PASSES**; if no matching parameter is found, **FAILS**.

## Non-compliant example
```hcl
resource "aws_redshift_parameter_group" "analytics" {
  name   = "analytics-cluster-params"
  family = "redshift-1.0"

  parameter {
    name  = "wlm_json_configuration"
    value = "[]"
  }
  # No require_ssl parameter -> SSL not enforced
}
```

## Remediated example
```hcl
resource "aws_redshift_parameter_group" "analytics" {
  name   = "analytics-cluster-params"
  family = "redshift-1.0"

  parameter {
    name  = "wlm_json_configuration"
    value = "[]"
  }

  parameter {
    name  = "require_ssl"
    value = "true"
  }
}
```

## Remediation steps
1. Add a `parameter` block with `name = "require_ssl"` and `value = "true"` (Terraform) or the equivalent `ParameterName`/`ParameterValue` pair (CloudFormation) to the Redshift cluster parameter group.
2. Associate this parameter group with the target `aws_redshift_cluster` via its `cluster_parameter_group_name` attribute if not already applied.
3. Update all client connection strings/JDBC-ODBC configurations to use SSL mode (e.g. `sslmode=require` or `sslmode=verify-full`) so connections don't simply fail once enforcement is turned on.
4. Applying a parameter group change generally requires a cluster reboot to take effect — plan for a brief maintenance window.
5. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedShiftSSL.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RedShiftSSL.py)
- [AWS Redshift: Configuring security options for connections](https://docs.aws.amazon.com/redshift/latest/mgmt/connecting-configure-ssl-support.html)
