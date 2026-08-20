# CKV_AWS_246: Ensure RDS Cluster activity streams are encrypted using KMS CMKs

## Severity
**LOW** (score: 2.0/10)

RDS Cluster Activity Streams carry near-real-time database activity (including SQL text and potentially sensitive query data) to Kinesis, and shipping that stream without KMS CMK encryption exposes highly sensitive audit/query data at rest.

## Summary
This check ensures that an RDS Cluster Database Activity Stream (`aws_rds_cluster_activity_stream`) is encrypted with a customer-managed KMS key.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_rds_cluster_activity_stream`

## Why it matters
RDS Database Activity Streams capture a near-real-time feed of all database activity (DDL, DML, queries, connection attempts) for compliance monitoring and threat detection, typically consumed via Kinesis. This stream inherently contains sensitive data — full SQL statements can include literal values from `INSERT`/`UPDATE` queries, meaning PII or secrets can flow through it. Requiring a CMK (rather than relying purely on the AWS-managed key AWS uses by default for activity streams) gives you independent control of key policies, the ability to audit every decrypt operation via CloudTrail, and the ability to revoke access to historical activity data by disabling the key — important since activity streams are often used specifically for security/forensic purposes and should not depend on the same trust boundary as the rest of the account's default encryption.

## How Checkov evaluates this
The check inspects the `kms_key_id` attribute of the resource with an expected value of `ANY_VALUE`.

- **PASS**: `kms_key_id` is set to any value.
- **FAIL**: `kms_key_id` is missing.

Note: `kms_key_id` is actually a *required* argument for this resource in the AWS provider, so in practice this check mainly catches cases where it's omitted in a way that would fail plan/apply anyway, or set via an unresolved/empty variable.

## Non-compliant example
```hcl
resource "aws_rds_cluster_activity_stream" "example" {
  resource_arn = aws_rds_cluster.example.arn
  mode         = "async"
  # kms_key_id omitted
}
```

## Remediated example
```hcl
resource "aws_kms_key" "activity_stream_cmk" {
  description         = "CMK for RDS cluster activity stream"
  enable_key_rotation = true
}

resource "aws_rds_cluster_activity_stream" "example" {
  resource_arn = aws_rds_cluster.example.arn
  mode         = "async"
  kms_key_id    = aws_kms_key.activity_stream_cmk.arn   # <-- added
}
```

## Remediation steps
1. Provision a dedicated customer-managed KMS key for the activity stream (do not reuse the database's own encryption key so you can independently scope access).
2. Set `kms_key_id` on `aws_rds_cluster_activity_stream` to that key's ARN.
3. Grant the RDS/Kinesis service roles the required `kms:Decrypt` and `kms:GenerateDataKey` permissions in the key policy.
4. Restrict IAM access to the CMK to the security/compliance team consuming the stream, separate from general database administrators.
5. Enable automatic key rotation and monitor `kms:Decrypt` CloudTrail events for anomalous access.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSClusterActivityStreamEncryptedWithCMK.py)
- [Terraform: aws_rds_cluster_activity_stream](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_activity_stream)
- [AWS: Database Activity Streams](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/DBActivityStreams.html)
