# CKV_AWS_316: Ensure CodeBuild project environments do not have privileged mode enabled

## Severity
**MEDIUM** (score: 5.0/10)

Privileged mode grants the CodeBuild container host-level Docker access, so a compromised or malicious build step can escape the intended container boundary and reach the underlying build host.

## Summary
This check ensures AWS CodeBuild projects do not run their build environment in Docker "privileged mode" unless it is genuinely required.

## Applicability
- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_codebuild_project`

## Why it matters
Privileged mode grants the CodeBuild build container full access to the host's devices and effectively disables container isolation (it's the mechanism required for Docker-in-Docker workflows, e.g. building container images inside a build). A build running in privileged mode that executes untrusted or third-party code (a compromised dependency, a malicious pull request in a public repo, a tampered build script) can break out of the container sandbox, access the underlying build host, tamper with other builds, exfiltrate the IAM role credentials attached to the build environment, or pivot further into the AWS account. This is a direct escalation-of-privilege / container-escape risk (mapped to NIST 800-53 AC-6, AC-6(10) — least privilege, and AC-3 — access enforcement), and it is one of the most common supply-chain attack vectors seen in real-world CI/CD compromises.

## How Checkov evaluates this
A `BaseResourceNegativeValueCheck` inspecting the nested key `environment[0].privileged_mode`:
- **FAIL** if `privileged_mode` is explicitly set to `true`.
- **PASS** if it is `false`, unset (defaults to `false`), or the environment block doesn't set it.

## Non-compliant example
```hcl
resource "aws_codebuild_project" "example" {
  name          = "example-build"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 30

  source {
    type     = "GITHUB"
    location = "https://github.com/example/example-repo.git"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/standard:7.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = true          # grants full host device access
  }
}
```

## Remediated example
```hcl
resource "aws_codebuild_project" "example" {
  name          = "example-build"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 30

  source {
    type     = "GITHUB"
    location = "https://github.com/example/example-repo.git"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/standard:7.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = false          # or omit the argument entirely
  }
}
```

## Remediation steps
1. Remove `privileged_mode = true` (or set it to `false`) unless the project genuinely needs to build or run Docker images as part of the build (Docker-in-Docker).
2. If Docker builds are required, isolate the privileged project to its own dedicated, tightly-scoped IAM service role with the minimum permissions needed, restrict the source repository to trusted, reviewed code only (no arbitrary PR builds from forks), and consider AWS CodeBuild's rootless/Buildkit-based image build support or AWS-managed image-building services (e.g., EC2 Image Builder, native ECR build features) as an alternative that avoids privileged mode.
3. Add branch/PR filtering so untrusted external contributions cannot trigger a privileged build.
4. This is a straightforward in-place configuration change with no resource replacement required.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CodeBuildPrivilegedMode.py
- AWS docs: https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-privileged.html
