# CKV_AWS_163: Ensure ECR image scanning on push is enabled

## Severity
**HIGH** (score: 7.5/10)

Disabling scan-on-push means known-vulnerable or malicious container images can be pushed and later deployed undetected, but the check only affects detection/visibility, not an active exposure by itself.

## Summary
This check requires that Elastic Container Registry (ECR) repositories automatically scan container images for known OS/package vulnerabilities every time an image is pushed.

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **Terraform**: `aws_ecr_repository`
- **CloudFormation**: `AWS::ECR::Repository`

## Why it matters
Container images are built from base images and package layers that frequently contain known CVEs (in OS packages, language runtimes, or third-party libraries). Without automatic scan-on-push, vulnerable images can be pushed to the registry and deployed to production with no automated visibility into their risk — vulnerabilities are only discovered if someone manually scans the image or after an incident occurs.

Enabling scan-on-push causes ECR (backed by Amazon Inspector or the basic scanning engine) to inspect every newly pushed image and surface CVE findings, which can then be wired into CI/CD gates, alerting, or admission control to block known-vulnerable images from reaching production. Skipping this leaves a systemic blind spot in the software supply chain — the exact gap exploited when attackers ship malicious or vulnerable dependencies that go undetected until exploited at runtime.

## How Checkov evaluates this
For Terraform, the check inspects the boolean value at `image_scanning_configuration[0].scan_on_push`. If this is not `true` (including when the `image_scanning_configuration` block is absent entirely), the check **FAILS**.

For CloudFormation, it inspects `Properties.ImageScanningConfiguration.ScanOnPush` and fails unless it is explicitly `true`.

## Non-compliant example
```hcl
resource "aws_ecr_repository" "app" {
  name                 = "app-image-repo"
  image_tag_mutability = "IMMUTABLE"
  # image_scanning_configuration not set -> scan_on_push defaults to false
}
```

## Remediated example
```hcl
resource "aws_ecr_repository" "app" {
  name                 = "app-image-repo"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true  # added
  }
}
```

## Remediation steps
1. Add an `image_scanning_configuration` block to the `aws_ecr_repository` resource with `scan_on_push = true` (Terraform), or set `ImageScanningConfiguration.ScanOnPush: true` (CloudFormation).
2. For existing repositories, this can be applied in-place without recreating the repository or its images.
3. Consider enabling ECR "enhanced scanning" (Amazon Inspector integration) at the registry level for continuous re-scanning of images already in the repository, not just at push time, since new CVEs are discovered after images are already stored.
4. Wire scan findings into CI/CD (e.g. fail a pipeline on CRITICAL/HIGH findings) or into automated alerting so scan results are actually acted upon, not just collected.
5. Combine with a repository lifecycle policy to prune old/vulnerable images that are no longer needed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECRImageScanning.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ECRImageScanning.py
- AWS docs: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
