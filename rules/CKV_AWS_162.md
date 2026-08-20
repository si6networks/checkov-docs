# CKV_AWS_162: Ensure RDS cluster has IAM authentication enabled

## Severity
**LOW** (score: 2.0/10)

As with single-instance RDS, skipping IAM authentication on a cluster leaves login dependent on durable shared passwords rather than centrally revocable IAM tokens, raising the impact of credential leakage without being directly exploitable on its own.

## Summary
This check requires that Aurora/RDS clusters have IAM database authentication enabled, allowing database logins to be authorized and audited through AWS IAM rather than static database passwords alone.

## Applicability
- **Terraform**: `aws_rds_cluster`
- **CloudFormation**: `AWS::RDS::DBCluster`

Unlike the single-instance check (CKV_AWS_161), this cluster-level check does **not** special-case the `engine` field in either implementation — it inspects the relevant attribute for all `aws_rds_cluster` / `AWS::RDS::DBCluster` resources unconditionally (in practice IAM auth for clusters is supported for Aurora MySQL and Aurora PostgreSQL).

## Why it matters
RDS/Aurora clusters typically back critical, shared application data stores. Relying solely on static master/application passwords for cluster access means a single leaked credential (from source control, logs, a compromised CI pipeline, or an old backup) grants durable, hard-to-revoke database access that bypasses IAM-based access control and auditing entirely. Because clusters can have many endpoints and read replicas, the blast radius of a leaked password is often larger than for a single instance.

Enabling IAM database authentication lets access be granted via short-lived (15-minute) tokens signed with IAM credentials, so:
- Access can be revoked immediately by removing IAM permissions, without needing to rotate a shared database password.
- Each connecting principal can be distinct (mapped to an IAM role/user), improving traceability of who accessed the cluster.
- The credential material used for authentication has a short lifetime, reducing the value of any single leaked token.

## How Checkov evaluates this
For Terraform, the check inspects the `iam_database_authentication_enabled` attribute of `aws_rds_cluster`. If it is not explicitly set to `true`, the check **FAILS** (this is a straightforward `BaseResourceValueCheck` with no engine-based exception, unlike CKV_AWS_161).

For CloudFormation, it inspects `Properties.EnableIAMDatabaseAuthentication` on `AWS::RDS::DBCluster` and fails if that value is not `true`.

## Non-compliant example
```hcl
resource "aws_rds_cluster" "app_cluster" {
  cluster_identifier = "app-aurora-cluster"
  engine              = "aurora-postgresql"
  engine_version      = "15.4"
  master_username     = "appadmin"
  master_password     = "changeme123!"
  # iam_database_authentication_enabled not set -> defaults to false
}
```

## Remediated example
```hcl
resource "aws_rds_cluster" "app_cluster" {
  cluster_identifier                  = "app-aurora-cluster"
  engine                              = "aurora-postgresql"
  engine_version                      = "15.4"
  master_username                     = "appadmin"
  master_password                     = "changeme123!"
  iam_database_authentication_enabled = true  # added
}
```

## Remediation steps
1. Set `iam_database_authentication_enabled = true` on the `aws_rds_cluster` resource (or `EnableIAMDatabaseAuthentication: true` in CloudFormation).
2. Verify the cluster's engine (Aurora MySQL or Aurora PostgreSQL) supports IAM authentication — check current AWS documentation, since support varies by engine version.
3. Create IAM policies granting `rds-db:connect` scoped to the cluster resource ID and specific database user(s).
4. Create the corresponding database-level IAM-mapped users (`CREATE USER ... WITH LOGIN; GRANT rds_iam TO ...` for Postgres-family, or the `AWSAuthenticationPlugin` approach for MySQL-family).
5. Update application/connection code to request short-lived auth tokens (`aws rds generate-db-auth-token`) and require SSL/TLS on the connection.
6. This is an in-place configuration change but requires supporting application changes; roll out gradually and keep existing password-based auth available during transition if needed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSClusterIAMAuthentication.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RDSClusterIAMAuthentication.py
- AWS docs: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/UsingWithRDS.IAMDBAuth.html
