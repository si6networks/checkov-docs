# CKV_AWS_71: Ensure Redshift Cluster logging is enabled
## Severity
**LOW** (score: 2.0/10)

Missing Redshift cluster logging removes the audit trail needed to detect and investigate unauthorized queries or access to the data warehouse, a monitoring gap rather than a direct exposure.

## Summary
This check fails when an Amazon Redshift cluster does not have audit/database logging enabled, meaning connection, user activity, and query logs are not captured.

## Applicability
- **IaC frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::Redshift::Cluster` (CloudFormation), `aws_redshift_cluster` (Terraform)
- **Check type:** resource

## Why it matters
Redshift logging (audit logging) records connection attempts, user activity, and executed queries to an S3 bucket (or CloudWatch, depending on configuration). Without it, there is no forensic trail for detecting unauthorized access, data exfiltration via queries, or misuse of database credentials. In a breach investigation, the absence of these logs means you cannot determine what data was accessed, by whom, or when — a critical gap for compliance regimes (PCI-DSS, HIPAA, SOC 2) that mandate audit trails for systems holding sensitive data. Since Redshift often serves as a central data warehouse aggregating data from many systems, an unlogged cluster represents an outsized blind spot in an organization's overall audit posture.

## How Checkov evaluates this
Both implementations extend `BaseResourceValueCheck`, which passes only if the inspected attribute is present and set to a truthy/expected value:
- **CloudFormation:** inspects `Properties/LoggingProperties/BucketName`. The expected value is `ANY_VALUE` — so the check passes as soon as any S3 bucket name is configured for logging destination; if `LoggingProperties.BucketName` is absent, it fails.
- **Terraform:** inspects the nested block `logging[0].enable`. The check passes only if `logging { enable = true }` is set; if the `logging` block is missing or `enable` is `false`/absent, it fails.

## Non-compliant example
```hcl
resource "aws_redshift_cluster" "analytics" {
  cluster_identifier = "analytics-cluster"
  database_name       = "analytics"
  master_username     = "admin"
  master_password     = "ChangeMe123!"
  node_type           = "dc2.large"
  cluster_type        = "single-node"
}
```

```yaml
Resources:
  AnalyticsCluster:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterIdentifier: analytics-cluster
      DBName: analytics
      MasterUsername: admin
      MasterUserPassword: ChangeMe123!
      NodeType: dc2.large
      ClusterType: single-node
```

## Remediated example
```hcl
resource "aws_redshift_cluster" "analytics" {
  cluster_identifier = "analytics-cluster"
  database_name       = "analytics"
  master_username     = "admin"
  master_password     = "ChangeMe123!"
  node_type           = "dc2.large"
  cluster_type        = "single-node"

  logging {
    enable        = true
    bucket_name   = "analytics-redshift-audit-logs"
    s3_key_prefix = "redshift/"
  }
}
```

```yaml
Resources:
  AnalyticsCluster:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterIdentifier: analytics-cluster
      DBName: analytics
      MasterUsername: admin
      MasterUserPassword: ChangeMe123!
      NodeType: dc2.large
      ClusterType: single-node
      LoggingProperties:
        BucketName: analytics-redshift-audit-logs
        S3KeyPrefix: redshift/
```

## Remediation steps
1. Add a `logging` block (Terraform) or `LoggingProperties` (CloudFormation) to the cluster resource.
2. Set `enable = true` (Terraform) and provide a destination S3 bucket name.
3. Ensure the target S3 bucket has a bucket policy granting Redshift's log-delivery service (`redshift.amazonaws.com` / the Redshift service account for the region) `s3:PutObject` and `s3:GetBucketAcl` permissions — Redshift will fail to deliver logs otherwise.
4. Consider enabling encryption and lifecycle policies on the log bucket, since audit logs themselves may contain sensitive query text.
5. This is a non-disruptive, in-place change — no cluster replacement/downtime is required.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RedshiftClusterLogging.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/RedshiftClusterLogging.py)
- [AWS Redshift database audit logging](https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html)
