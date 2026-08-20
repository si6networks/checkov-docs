# CKV2_AWS_49: Ensure AWS Database Migration Service endpoints have SSL configured
## Severity
**HIGH** (score: 7.0/10)

A DMS endpoint without SSL configured transmits potentially sensitive database contents in cleartext during migration, exposing data in transit to interception.

## Summary
This check fails when a DMS (Database Migration Service) endpoint's engine requires an explicit SSL mode and `ssl_mode` is left as `none`, meaning data replicated to/from that endpoint travels unencrypted.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource/entity types:** `aws_dms_endpoint`

## Why it matters
DMS endpoints frequently move production databases — including full table contents, PII, credentials stored in application tables, and financial data — across network boundaries, sometimes over the public internet or between VPCs/accounts. If `ssl_mode` is `none` for an endpoint whose underlying engine supports/requires TLS (e.g. `mysql`, `postgres`, `oracle`, `sqlserver`, `mariadb`), all of that replicated data, along with the database credentials DMS uses to connect, is sent in cleartext. This exposes the migration/replication traffic to network-level eavesdropping (packet capture on a shared subnet, a compromised network device, or a misconfigured VPC peering/transit gateway route) and to man-in-the-middle tampering, since there's no certificate validation happening either. Because DMS migrations/replications are often long-running (ongoing CDC replication, not just a one-time cutover), an unencrypted endpoint represents a standing exposure window rather than a brief one.

## How Checkov evaluates this
This is a graph-based JSON policy with three top-level `or` branches, plus special-cased engine exemptions:
1. **Source endpoints:** PASS if `endpoint_type = "source"` and either `engine_name` is one of `s3` or `azuredb` (engines Checkov treats as not requiring/exposing this SSL setting the same way), OR `ssl_mode` is not `"none"`.
2. **Target endpoints:** PASS if `endpoint_type = "target"` and either `engine_name` is one of `dynamodb`, `kinesis`, `neptune`, `redshift`, `s3`, `elasticsearch`, `kafka` (engines exempted from this rule), OR `ssl_mode` is not `"none"`.
3. **Any other endpoint_type** value (not `source` or `target`) automatically passes.
- **FAIL** occurs when the endpoint is a `source` or `target` for one of the SSL-relevant engines (e.g. `mysql`, `postgres`, `oracle`, `sqlserver`, `mariadb`, `sybase`, `db2`, `mongodb`) and `ssl_mode` is left at `none` (or unset, defaulting to `none`).

## Non-compliant example
```hcl
resource "aws_dms_endpoint" "bad" {
  endpoint_id   = "source-postgres"
  endpoint_type = "source"
  engine_name   = "postgres"
  server_name   = "db.example.internal"
  port          = 5432
  username      = "dms_user"
  password      = var.db_password
  database_name = "appdb"
  ssl_mode      = "none"
}
```

## Remediated example
```hcl
resource "aws_dms_endpoint" "good" {
  endpoint_id   = "source-postgres"
  endpoint_type = "source"
  engine_name   = "postgres"
  server_name   = "db.example.internal"
  port          = 5432
  username      = "dms_user"
  password      = var.db_password
  database_name = "appdb"
  ssl_mode      = "require"
}
```

## Remediation steps
1. Identify the endpoint's `engine_name`; if it's a relational/database engine (mysql, postgres, oracle, sqlserver, mariadb, etc.), TLS is expected.
2. Set `ssl_mode` to `require` (encrypts without verifying the server certificate) or, preferably, `verify-ca` / `verify-full` if you have a CA certificate you can register via `aws_dms_certificate` and reference with `certificate_arn`.
3. Ensure the source/target database itself is configured to accept and enforce TLS connections (e.g. `rds.force_ssl` parameter for RDS Postgres, `require_secure_transport` for MySQL).
4. For engines exempted by this check (S3, DynamoDB, Kinesis, Redshift, Elasticsearch, Kafka, Neptune, AzureDB), encryption in transit is typically handled by the service's own transport (HTTPS API endpoints) rather than the DMS `ssl_mode` field.
5. Changing `ssl_mode` on an existing endpoint typically does not require replacement, but verify connectivity/certificate trust before cutting over production replication tasks to avoid connection failures.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/DMSEndpointHaveSSLConfigured.json
- AWS docs: https://docs.aws.amazon.com/dms/latest/userguide/security-encryption-ssl.html
