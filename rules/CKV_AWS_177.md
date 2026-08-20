# CKV_AWS_177: Ensure Kinesis Video Stream is encrypted by KMS using a customer managed Key (CMK)

## Severity
**LOW** (score: 2.0/10)

Encrypting a Kinesis Video Stream with the default AWS-managed key instead of a customer-managed key reduces control over key rotation and access auditing for potentially sensitive video/audio data, a moderate confidentiality gap rather than an active exposure.

## Summary
This check requires that an Amazon Kinesis Video Stream resource specifies a KMS key ID for at-rest encryption of stream data, rather than relying on default/unspecified key configuration.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_kinesis_video_stream`

## Why it matters
Kinesis Video Streams typically ingest continuous, potentially sensitive media — security camera feeds, connected-vehicle sensor/video data, industrial monitoring footage, or other audio/video streams that can capture people, locations, and behaviors with high sensitivity. If the stream is not encrypted with an explicit customer-managed KMS key, at-rest protection relies on Kinesis Video Streams' default AWS-managed key, which cannot be scoped with a custom key policy limiting exactly which principals can decrypt stored video fragments, and cannot be independently revoked or audited per-application.

Given the highly sensitive nature of video/audio data (subject to privacy regulations like GDPR/CCPA/BIPA in many jurisdictions, and often containing PII by nature — faces, license plates, voices), using a customer-managed KMS key allows the organization to enforce strict access boundaries (e.g. only specific analytics/playback roles can decrypt), maintain a dedicated CloudTrail audit trail of every decrypt operation, and revoke access to historical footage independently of other AWS services sharing the account's default key.

## How Checkov evaluates this
The check inspects the `kms_key_id` attribute on `aws_kinesis_video_stream`. It **PASSES** if this attribute is present with any non-empty value (`ANY_VALUE` sentinel — it does not verify the key is specifically a customer-managed key as opposed to an AWS-managed alias, only that a key ID/ARN is explicitly configured). If `kms_key_id` is absent, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_kinesis_video_stream" "camera_feed" {
  name                    = "front-door-camera"
  data_retention_in_hours = 24
  # kms_key_id not set -> uses Kinesis Video Streams default encryption
}
```

## Remediated example
```hcl
resource "aws_kms_key" "video_streams" {
  description             = "CMK for Kinesis Video Stream encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kinesis_video_stream" "camera_feed" {
  name                    = "front-door-camera"
  data_retention_in_hours = 24
  kms_key_id              = aws_kms_key.video_streams.arn  # added
}
```

## Remediation steps
1. Create (or identify) a customer-managed KMS key intended for video stream encryption, ideally with `enable_key_rotation = true` and a key policy scoping decrypt access to only the specific roles/services (e.g. a video-processing Lambda, a playback service) that need it.
2. Set `kms_key_id` on the `aws_kinesis_video_stream` resource to that key's ARN or key ID.
3. Grant the Kinesis Video Streams service and any consuming applications (GetMedia/GetHLSStreamingSessionURL callers, media pipelines) `kms:Decrypt`/`kms:GenerateDataKey` permissions on the key policy, or stream operations will fail with access-denied errors.
4. Note: `kms_key_id` is generally only configurable at stream creation in most provider versions — changing it on an existing stream typically requires resource replacement; plan for a new stream and re-pointing producers/consumers rather than expecting a seamless in-place update.
5. Combine with strict IAM policies on `kinesisvideo:GetDataEndpoint`/`GetMedia` actions so that even encrypted stream access is limited to intended consumers.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KinesisVideoEncryptedWithCMK.py
- AWS docs: https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_CreateStream.html
