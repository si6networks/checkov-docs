# CKV_AWS_372: Ensure Amazon SageMaker Flow Definition uses KMS for output configurations

## Severity
**LOW** (score: 2.0/10)

Missing a customer-managed key for human-review workflow output reduces independent auditability and revocability of access to potentially sensitive reviewed data, particularly relevant for third-party/crowd-sourced reviewer workforces, but does not itself expose the data.

## Summary
This check ensures that an `aws_sagemaker_flow_definition` resource (used for Amazon SageMaker Ground Truth / Augmented AI human-review workflows) specifies a KMS key to encrypt its output data.

## Applicability
- **IaC framework:** Terraform
- **Check type:** resource check
- **Entities:** `aws_sagemaker_flow_definition`

## Why it matters
A SageMaker Flow Definition configures a human-in-the-loop review workflow (Amazon Augmented AI / A2I): low-confidence model predictions are routed to human reviewers (often internal staff or Mechanical Turk workers) who label/correct them, and the results are written to an S3 output location. This output frequently contains a mix of the original inference input (which may include PII or business-sensitive data) and the human reviewer's judgment/corrections. Without a customer-managed KMS key specified, output data relies on weaker default encryption controls, meaning the organization can't independently audit key usage (via CloudTrail `kms:Decrypt` events), enforce a key policy scoping which roles/services can decrypt this potentially sensitive review data, or rapidly revoke access via key-level controls if reviewer credentials are compromised. This is especially important for third-party or crowd-sourced (Mechanical Turk) reviewer workflows, where the workforce isn't part of your own organization's trust boundary.

## How Checkov evaluates this
Attribute-value check (`BaseResourceValueCheck`) using `ANY_VALUE` — it verifies only that `output_config[0].kms_key_id` is set to some non-empty value, not a specific key. If absent, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_sagemaker_flow_definition" "review_flow" {
  flow_definition_name = "prediction-review-flow"
  role_arn              = aws_iam_role.sagemaker_a2i.arn

  human_loop_config {
    human_task_ui_arn         = aws_sagemaker_human_task_ui.review_ui.arn
    task_count                = 1
    task_description          = "Review low-confidence predictions"
    task_title                = "Prediction Review"
    workteam_arn               = aws_sagemaker_workteam.reviewers.arn
  }

  output_config {
    s3_output_path = "s3://a2i-output-bucket/reviews/"
    # No kms_key_id set
  }
}
```

## Remediated example
```hcl
resource "aws_sagemaker_flow_definition" "review_flow" {
  flow_definition_name = "prediction-review-flow"
  role_arn              = aws_iam_role.sagemaker_a2i.arn

  human_loop_config {
    human_task_ui_arn         = aws_sagemaker_human_task_ui.review_ui.arn
    task_count                = 1
    task_description          = "Review low-confidence predictions"
    task_title                = "Prediction Review"
    workteam_arn               = aws_sagemaker_workteam.reviewers.arn
  }

  output_config {
    s3_output_path = "s3://a2i-output-bucket/reviews/"
    kms_key_id     = aws_kms_key.a2i_output.arn
  }
}
```

## Remediation steps
1. Create (or identify) a customer-managed KMS key for the human-review output data.
2. Set `kms_key_id` inside the `output_config` block to that key's ARN.
3. Grant the `role_arn` execution role (and, if applicable, the reviewer/workforce IAM roles that need to write results) appropriate `kms:GenerateDataKey`/`kms:Decrypt` permissions in the key policy.
4. Flow Definitions are effectively immutable once created — this must be set at creation time, or requires creating a new flow definition and repointing any dependent human-review integrations.
5. Also ensure the destination S3 bucket's bucket policy/ACLs don't independently grant broader access that would bypass the intent of key-level access control.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/SagemakerFlowDefinitionUsesKMS.py
- AWS docs: https://docs.aws.amazon.com/sagemaker/latest/dg/a2i-create-flow-definition.html
