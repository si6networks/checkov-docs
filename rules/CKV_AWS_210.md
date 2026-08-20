# CKV_AWS_210: Batch job does not define a privileged container
## Severity
**LOW** (score: 2.0/10)

A privileged container in an AWS Batch job definition can access the host's devices and kernel capabilities, providing a path to container breakout and host compromise if the job or its image is compromised.

## Summary
This check ensures that AWS Batch job definitions do not configure their container to run with the `privileged` flag enabled, which would grant the container elevated access to the host system.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_batch_job_definition`

## Why it matters
A privileged container in a Docker/ECS/Batch context runs with nearly all of the capabilities of the host machine — it can access host devices, modify kernel parameters, and in many cases break out of container isolation entirely. AWS Batch jobs execute as containers on ECS-managed (or Fargate) compute; if the job definition's `container_properties` sets `privileged: true`, any code that runs inside that batch job (including a compromised dependency, a malicious input processed by the job, or an attacker who can submit/modify job parameters) gains a much larger attack surface to pivot from the container into the underlying host or other containers sharing that host. Since Batch jobs are often used for automated, unattended data-processing pipelines, a privileged escape here can lead to lateral movement across the compute fleet with no interactive session to notice it.

## How Checkov evaluates this
The check reads the `container_properties` attribute of the `aws_batch_job_definition` resource. This attribute is typically supplied as a JSON string (via `jsonencode(...)` or a literal string), so the check:
1. Retrieves `container_properties` from the resource config.
2. If it is a string, it attempts to `json.loads()` it into a dict (a JSON decode failure results in `UNKNOWN`, since Checkov cannot statically evaluate the container spec).
3. If it is not a string, it assumes it is already a dict.
4. If the parsed result is not a dict, returns `UNKNOWN`.
5. If the resulting dict has a truthy `privileged` key, the check **FAILS**.
6. Otherwise (privileged absent or falsy), the check **PASSES**.
7. If `container_properties` is missing entirely, the result is `UNKNOWN` (Checkov cannot determine privilege status without it).

## Non-compliant example
```hcl
resource "aws_batch_job_definition" "example" {
  name = "batch-job-def"
  type = "container"

  container_properties = jsonencode({
    image      = "busybox"
    vcpus      = 2
    memory     = 2048
    privileged = true
    command    = ["echo", "test"]
  })
}
```

## Remediated example
```hcl
resource "aws_batch_job_definition" "example" {
  name = "batch-job-def"
  type = "container"

  container_properties = jsonencode({
    image      = "busybox"
    vcpus      = 2
    memory     = 2048
    privileged = false
    command    = ["echo", "test"]
  })
}
```

## Remediation steps
1. Locate the `container_properties` block (or JSON-encoded string) in your `aws_batch_job_definition` resource.
2. Remove the `privileged` key, or explicitly set it to `false`.
3. If the workload genuinely requires elevated host access (e.g. certain device access or kernel-module tasks), scope the specific capability needed using `linuxParameters.devices` or `capabilities.add` instead of full privileged mode, and document why via an exception/suppression comment.
4. Re-run `checkov -d .` to confirm the resource now passes.
5. Note: changing `container_properties` typically only affects new job submissions using the updated job definition revision — existing running jobs are unaffected until resubmitted.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/BatchJobIsNotPrivileged.py)
- [AWS Batch container properties documentation](https://docs.aws.amazon.com/batch/latest/APIReference/API_ContainerProperties.html)
