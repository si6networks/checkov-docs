# CKV2_AWS_69: Ensure AWS RDS database instance configured with encryption in transit

## Severity
**MEDIUM** (score: 5.0/10)

Allowing unencrypted client connections to an RDS database exposes query traffic and credentials in transit to network-level interception, a serious confidentiality gap for what is typically a sensitive data store.

## Summary
This check requires RDS instances to enforce TLS/SSL-encrypted connections at the database engine level via the connected parameter group — specifically `rds.force_ssl` (PostgreSQL/SQL Server), `require_secure_transport` (MySQL/MariaDB), or `db2comm=SSL` (Db2) — rather than allowing unencrypted client connections.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::RDS::DBInstance` + `AWS::RDS::DBParameterGroup` (CloudFormation); `aws_db_instance` + `aws_db_parameter_group` (Terraform)

## Why it matters
Even when RDS storage is encrypted at rest, data traveling between the application and the database over the network is plaintext by default unless the engine is explicitly configured to require TLS. Database traffic — including full query text, result sets, and authentication credentials on connection setup — can be intercepted by anyone with visibility into the network path: a compromised host on the same VPC/subnet, a misconfigured security group allowing broader access than intended, a malicious insider with network tap access, or traffic traversing peered VPCs/Transit Gateway where trust boundaries are less clear. Forcing SSL/TLS (`rds.force_ssl=1`, `require_secure_transport=ON`) ensures the database engine itself rejects any unencrypted connection attempt, rather than relying on every application and every database client being correctly configured to opt into TLS — a much weaker guarantee, since a single misconfigured client silently falls back to plaintext.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy) with per-engine-family logic. For an `aws_db_instance` / `AWS::RDS::DBInstance`:
- **If no connected parameter group exists at all**, the check **PASSES** (it can't evaluate what it can't see — this is a permissive default for instances using the engine's default parameter group).
- **If a parameter group is connected**, the check evaluates per engine family (via `family` regex match), requiring ALL of the following sub-conditions to hold:
  - For Postgres/SQL Server families (`family` matches `^postgres.*` or `.*sqlserver.*`): either the family doesn't match at all, OR the parameter `rds.force_ssl` exists and equals `"1"`.
  - For MariaDB/MySQL families (`family` matches `^(mariadb|mysql).*`): either the family doesn't match, OR the parameter `require_secure_transport` exists and equals `"1"`.
  - For Db2 (`family` matches `.*db2-ae.*`): either the family doesn't match, OR the parameter `db2comm` exists and equals `"SSL"`.

In short: if you attach a parameter group for a covered engine family, that family's specific SSL-enforcing parameter must be explicitly set. Engines/families not covered by any of the three regexes automatically satisfy their branch (vacuously true).

## Non-compliant example
```hcl
resource "aws_db_parameter_group" "postgres_params" {
  name   = "app-postgres-params"
  family = "postgres15"

  # rds.force_ssl not set -> connections not required to use TLS -> FAILS
  parameter {
    name  = "log_connections"
    value = "1"
  }
}

resource "aws_db_instance" "app_db" {
  identifier           = "app-prod-db"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.r6g.large"
  allocated_storage    = 100
  parameter_group_name = aws_db_parameter_group.postgres_params.name
}
```

## Remediated example
```hcl
resource "aws_db_parameter_group" "postgres_params" {
  name   = "app-postgres-params"
  family = "postgres15"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name         = "rds.force_ssl"
    value        = "1"           # added: enforce TLS for all client connections
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "app_db" {
  identifier           = "app-prod-db"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.r6g.large"
  allocated_storage    = 100
  parameter_group_name = aws_db_parameter_group.postgres_params.name
}
```

## Remediation steps
1. Identify the engine family of each RDS instance's parameter group and set the corresponding TLS-enforcement parameter: `rds.force_ssl=1` for PostgreSQL/SQL Server, `require_secure_transport=ON`/`1` for MySQL/MariaDB, `db2comm=SSL` for Db2.
2. Some of these parameters require `apply_method = "pending-reboot"` and take effect only after the next maintenance window or manual reboot — plan for a reboot/downtime window.
3. Ensure application connection strings and drivers are updated to use `sslmode=require` (Postgres), `useSSL=true` (MySQL/MariaDB JDBC), or equivalent — once the server enforces TLS, non-TLS clients will be rejected, so validate connectivity in staging first.
4. If using the default (unmanaged) parameter group, you must create a custom `aws_db_parameter_group`/`AWS::RDS::DBParameterGroup` since AWS default parameter groups cannot be modified.
5. Distribute the CA bundle (e.g., AWS RDS root CA) to application hosts if you also want to verify the server certificate (`sslmode=verify-full`), which this check does not itself require but is a stronger posture.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/RDSEncryptionInTransit.json
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/graph_checks/RDSEncryptionInTransit.json
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html
