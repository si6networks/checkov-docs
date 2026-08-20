# CKV_AWS_160: Ensure that Timestream database is encrypted with KMS CMK
## Severity
**MEDIUM** (score: 5.0/10)

Timestream databases typically hold time-series telemetry, and encrypting with a customer-managed CMK rather than a default key strengthens at-rest protection and key-access control for that data, an incremental hardening rather than a fix for wholly unencrypted storage.

## Summary
This check verifies that an Amazon Timestream database specifies a KMS key for encrypting its stored time-series data.

## Applicability
Terraform (`aws_timestreamwrite_database`) and CloudFormation (`AWS::Timestream::Database`).

## Why it matters
Timestream databases commonly store high-volume telemetry, IoT sensor readings, application metrics, and operational data — which can include device identifiers, location data, or usage patterns tied to individuals or business-sensitive operational details. By default, Timestream encrypts data with an AWS-owned key that offers no customer-controlled key policy, no independent audit trail of decrypt operations, and no ability to revoke access to the data independent of Timestream's own IAM permissions. Specifying a customer-managed KMS key (CMK) lets you enforce a dedicated key policy restricting which principals may decrypt the data, get a full CloudTrail record of every key usage, and instantly cut off access by disabling the key — an important control for time-series data that may need to be embargoed or purged under data-retention/compliance requirements.

## How Checkov evaluates this
`BaseResourceValueCheck` with `ANY_VALUE` as expected value, inspecting `kms_key_id` (Terraform) / `Properties.KmsKeyId` (CloudFormation). Passes if set to any non-empty value (a customer-managed key ARN/ID); fails if the attribute is absent, meaning the database relies on the default AWS-owned key.

## Non-compliant example
```hcl
resource "aws_timestreamwrite_database" "telemetry" {
  database_name = "iot-telemetry"
  # no kms_key_id -> uses AWS-owned default key
}
```

## Remediated example
```hcl
resource "aws_kms_key" "timestream" {
  description             = "CMK for Timestream telemetry database"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_timestreamwrite_database" "telemetry" {
  database_name = "iot-telemetry"
  kms_key_id    = aws_kms_key.timestream.arn # <-- added
}
```

## Remediation steps
1. Create a customer-managed KMS key dedicated to Timestream data (or a shared data-platform CMK), with a key policy granting the Timestream service and relevant application roles `kms:Decrypt`/`kms:GenerateDataKey`.
2. Set `kms_key_id` (Terraform) or `KmsKeyId` (CloudFormation) on the `aws_timestreamwrite_database`/`AWS::Timestream::Database` resource.
3. Note: changing the KMS key on an existing Timestream database re-encrypts data with the new key going forward — verify IAM/key policy changes are propagated before cutting write/read traffic over, to avoid access errors.
4. Enable key rotation (`enable_key_rotation = true`) on the CMK for ongoing key hygiene.
5. Review associated Timestream tables' magnetic/memory store retention settings alongside encryption to ensure data lifecycle and protection policies are aligned.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/TimestreamDatabaseKMSKey.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/TimestreamDatabaseKMSKey.py
- AWS docs: https://docs.aws.amazon.com/timestream/latest/developerguide/EncryptionAtRest.html
