# CKV_AWS_112: Ensure Session Manager data is encrypted in transit

## Severity
**MEDIUM** (score: 5.0/10)

Session Manager sessions can carry sensitive interactive-shell input/output and credentials, so transmitting that data without KMS encryption in transit risks interception of privileged session content.

## Summary
Fails when an AWS Systems Manager (SSM) `Session` document does not configure a KMS key (`kmsKeyId`) to encrypt Session Manager session data.

## Applicability
- **Terraform**: `aws_ssm_document` resource, specifically ones where `document_type = "Session"`.

## Why it matters
AWS Systems Manager Session Manager gives interactive shell/port-forwarding access to EC2 instances and other managed nodes without opening inbound SSH/RDP ports. By default, the session data stream between the client and the managed instance is protected by TLS, but AWS additionally supports layering KMS encryption on top so that session data (including any sensitive command output, credentials typed into a shell, or file contents transferred) is further protected end-to-end and access to decrypt it is governed by the KMS key policy. Without a KMS key configured, session data still traverses TLS but loses the additional key-management control, auditability (KMS API calls are logged in CloudTrail), and defense-in-depth that a customer-managed key provides — meaning a break in the transport layer or a misconfigured relay is not backstopped by a second encryption layer under the customer's own key control.

## How Checkov evaluates this
The check only evaluates `aws_ssm_document` resources where `document_type == ["Session"]` and a `content` attribute is present; otherwise it returns `UNKNOWN` (not evaluated). It then:
1. Determines `document_format` (defaults to `JSON`).
2. Parses the `content` string as JSON or YAML accordingly (or uses it directly if already a dict).
3. Extracts the `inputs` object from the parsed content.
4. **FAIL** if `inputs` exists but does not contain a truthy `kmsKeyId`.
5. **PASS** otherwise (i.e., `inputs.kmsKeyId` is set).

## Non-compliant example
```hcl
resource "aws_ssm_document" "session" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Document to hold regional settings for Session Manager"
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName            = "session-logs-bucket"
      s3EncryptionEnabled     = true
      cloudWatchLogGroupName  = ""
      cloudWatchEncryptionEnabled = false
      idleSessionTimeout      = "20"
    }
  })
}
```

## Remediated example
```hcl
resource "aws_ssm_document" "session" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Document to hold regional settings for Session Manager"
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName                = "session-logs-bucket"
      s3EncryptionEnabled         = true
      cloudWatchLogGroupName      = ""
      cloudWatchEncryptionEnabled = false
      idleSessionTimeout          = "20"
      kmsKeyId                    = aws_kms_key.session_manager.key_id
    }
  })
}

resource "aws_kms_key" "session_manager" {
  description             = "CMK for Session Manager encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key intended for Session Manager encryption, with an appropriate key policy granting the SSM service and the relevant IAM principals `kms:GenerateDataKey`/`kms:Decrypt`.
2. Add `kmsKeyId` to the `inputs` block of the `Session` document content, pointing at that key's ID or ARN.
3. If you manage this setting via the SSM console/Preferences page instead of a custom document, ensure the account-level Session Manager preferences also specify a KMS key — Checkov only inspects `aws_ssm_document` resources though, not the account-wide default preferences.
4. Confirm IAM roles used by instances and users have permission to use the KMS key; a missing `kms:Decrypt` grant will cause session start failures once encryption is enabled.
5. This is a preferences-level change with no resource replacement required; existing sessions are unaffected, new sessions pick up the setting.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SSMSessionManagerDocumentEncryption.py
- AWS documentation: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-encrypt-key.html
