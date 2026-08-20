# CKV_AWS_161: Ensure RDS database has IAM authentication enabled

## Severity
**MEDIUM** (score: 5.0/10)

Reliance on static, long-lived DB passwords instead of short-lived IAM-signed tokens increases the blast radius of a leaked credential, but exploitation still requires network access to the database and a separate secret compromise.

## Summary
This check requires that RDS database instances use IAM database authentication instead of (or in addition to) native database passwords, so that database login is tied to centrally managed AWS IAM identities.

## Applicability
- **Terraform**: `aws_db_instance`
- **CloudFormation**: `AWS::RDS::DBInstance`

The check only evaluates instances whose `engine` is `mysql` or `postgres` — for any other engine (e.g. `oracle-se2`, `sqlserver-ex`, `mariadb`) the check returns `UNKNOWN` and is effectively skipped, because IAM database authentication is only supported by AWS for MySQL and PostgreSQL engines.

## Why it matters
Traditional RDS authentication relies on long-lived database passwords that are frequently embedded in application config, environment variables, or secrets managers, and rarely rotated. If such a password leaks (via a config file committed to source control, a compromised app server, or a misconfigured secrets store), an attacker gets durable database access that is invisible to IAM-based auditing and not automatically revoked when an employee's AWS access is disabled.

IAM database authentication replaces static passwords with short-lived (15-minute) authentication tokens generated via the AWS SDK/CLI and signed with the caller's IAM credentials. This means:
- Access can be granted/revoked instantly through IAM policy, without rotating a database secret.
- Database logins are automatically covered by CloudTrail-adjacent IAM auditing and can be tied to individual IAM users/roles rather than a shared password.
- There is no long-lived secret to leak in the first place for authenticated sessions using this mechanism.

## How Checkov evaluates this
For Terraform, the check reads the `engine` attribute of `aws_db_instance`. If `engine` is not `mysql` or `postgres`, the result is `UNKNOWN` (not applicable). Otherwise it inspects the boolean attribute `iam_database_authentication_enabled`: if it is not set to `true`, the check **FAILS**.

For CloudFormation, the equivalent logic reads `Properties.Engine`; if it's not `mysql` or `postgres` the result is `UNKNOWN`. Otherwise it inspects `Properties.EnableIAMDatabaseAuthentication` and fails if it is not `true`.

## Non-compliant example
```hcl
resource "aws_db_instance" "app_db" {
  identifier        = "app-db"
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = "db.t3.medium"
  allocated_storage = 20
  username          = "appuser"
  password          = "changeme123!"
  # iam_database_authentication_enabled not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_db_instance" "app_db" {
  identifier                          = "app-db"
  engine                              = "postgres"
  engine_version                      = "15.4"
  instance_class                      = "db.t3.medium"
  allocated_storage                   = 20
  username                            = "appuser"
  password                            = "changeme123!"
  iam_database_authentication_enabled = true  # added
}
```

## Remediation steps
1. Confirm the instance's `engine` is `mysql` or `postgres` — IAM authentication is not supported for other engines (Oracle, SQL Server, MariaDB), so this control does not apply to them.
2. Set `iam_database_authentication_enabled = true` (Terraform) or `EnableIAMDatabaseAuthentication: true` (CloudFormation).
3. Create IAM policies granting `rds-db:connect` scoped to the specific DB resource ARN and database user, and attach them to the roles/users that need database access.
4. Create a corresponding database user (via `CREATE USER ... WITH LOGIN; GRANT rds_iam TO ...` for Postgres, or `CREATE USER ... IDENTIFIED WITH AWSAuthenticationPlugin` for MySQL) mapped to the IAM role.
5. Update application connection logic to generate an auth token via `aws rds generate-db-auth-token` (or the equivalent SDK call) instead of using a static password, and force SSL/TLS on the connection (IAM auth requires an encrypted connection).
6. This is a non-disruptive, in-place setting change (no replacement required), but existing application code must be updated to use token-based auth or logins using the old password method may need to remain available during migration.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSIAMAuthentication.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RDSIAMAuthentication.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html
