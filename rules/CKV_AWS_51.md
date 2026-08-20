# CKV_AWS_51: Ensure ECR Image Tags are immutable
## Severity
**LOW** (score: 2.0/10)

Mutable ECR image tags allow a previously-scanned or trusted tag to be silently overwritten with a different (potentially malicious) image, undermining supply-chain integrity guarantees for anything that deploys by tag.

## Summary
This check ensures Amazon ECR repositories have image tag immutability enabled, preventing an existing image tag (e.g., `latest`, `v1.2.3`) from being overwritten by a different image.

## Applicability
- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::ECR::Repository` (CloudFormation), `aws_ecr_repository` (Terraform)

## Why it matters
When image tags are mutable, anyone with push access to a repository can silently replace the image referenced by an existing tag — including tags already deployed to production or referenced by a running Kubernetes/ECS deployment. This creates both a supply-chain integrity risk and an incident-response blind spot: a compromised CI/CD credential or malicious insider could overwrite a trusted tag (e.g., `prod-stable`) with a backdoored image, and downstream systems that reference the tag by name (rather than by immutable digest) would pull the malicious image without any indication that anything changed. It also breaks reproducibility and auditability — you can no longer trust that "version 1.2.3" refers to the same bytes it did last week, which undermines rollback safety and forensic analysis after an incident.

## How Checkov evaluates this
Both implementations are `BaseResourceValueCheck` with an expected value of `"IMMUTABLE"`:
- **CloudFormation:** inspects `Properties/ImageTagMutability` on `AWS::ECR::Repository` — **PASS** if `"IMMUTABLE"`, **FAIL** if `"MUTABLE"` or absent (ECR defaults to `MUTABLE`).
- **Terraform:** inspects the `image_tag_mutability` argument on `aws_ecr_repository` — **PASS** if `"IMMUTABLE"`, **FAIL** if `"MUTABLE"` or absent.

## Non-compliant example
```hcl
resource "aws_ecr_repository" "example" {
  name = "example-app"
  # image_tag_mutability not set -> defaults to MUTABLE
}
```

## Remediated example
```hcl
resource "aws_ecr_repository" "example" {
  name                 = "example-app"
  image_tag_mutability = "IMMUTABLE"
}
```

## Remediation steps
1. Set `image_tag_mutability = "IMMUTABLE"` on the `aws_ecr_repository` resource (or `Properties/ImageTagMutability: IMMUTABLE` in CloudFormation).
2. Update CI/CD pipelines to push each build under a unique, immutable tag (e.g., a git SHA or semantic version) rather than repeatedly overwriting a shared tag like `latest`.
3. If a mutable "floating" tag pattern is genuinely needed (e.g., `staging-latest` for a fast-moving environment), consider a separate, clearly-labeled repository or use ECR's tag-immutability exclusion filters (available in newer ECR features) rather than disabling immutability repo-wide.
4. This setting can be updated on an existing repository without replacement or downtime, but note it only prevents *future* tag overwrites — it doesn't retroactively protect tags that were already mutable.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ECRImmutableTags.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ECRImmutableTags.py)
- [AWS ECR image tag mutability documentation](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html)
