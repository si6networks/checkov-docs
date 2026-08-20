# CKV_AWS_312: Ensure Elastic Beanstalk environments have enhanced health reporting enabled

## Severity
**HIGH** (score: 7.5/10)

Disabled enhanced health reporting reduces operational visibility into environment health, an availability/monitoring gap rather than a direct confidentiality or access-control weakness.

## Summary
This check ensures Elastic Beanstalk environments are configured with "Enhanced" health reporting (via `HealthStreamingEnabled`), rather than the basic health reporting system, so operational teams get detailed, near-real-time health and causal data.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform (AWS provider)
- **Resource type:** `aws_elastic_beanstalk_environment`

## Why it matters
Elastic Beanstalk's basic health reporting only reports a coarse "OK / Warning / Degraded / Severe" status derived from Auto Scaling and ELB metrics, with no visibility into the root cause. Enhanced health reporting adds per-instance application and OS-level health data (process status, deployment status, causes of degradation) and can stream that data to CloudWatch Logs. Without it, operators lose the ability to promptly identify *why* an environment degraded (e.g., failed deployments, out-of-memory processes, or misconfigured health checks), which delays incident response and undermines continuous monitoring obligations (NIST 800-53 CA-7, SI-2 — flaw remediation and system monitoring). In a security-review context this matters because a degraded/unhealthy environment is often the first sign of exploitation attempts, resource exhaustion attacks, or a broken deployment introducing a vulnerability.

## How Checkov evaluates this
Elastic Beanstalk options are configured via repeated `setting` blocks with `namespace`/`name`/`value` triples rather than dedicated arguments. The check iterates over all `setting` blocks looking for the one where:
- `namespace == "aws:elasticbeanstalk:healthreporting:system"`, and
- `name == "HealthStreamingEnabled"`

It **PASSES** only if that setting exists and its `value` is `"True"` (string) or a truthy boolean. If no matching setting is found, or the value is `"False"`/absent, the check **FAILS**. (Note: the underlying enhanced-health setting is actually `SystemType = enhanced`; this specific check targets the `HealthStreamingEnabled` flag used to stream enhanced health data to CloudWatch Logs.)

## Non-compliant example
```hcl
resource "aws_elastic_beanstalk_environment" "example" {
  name                = "example-env"
  application         = aws_elastic_beanstalk_application.example.name
  solution_stack_name = "64bit Amazon Linux 2 v5.8.0 running Node.js 18"

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "InstanceType"
    value     = "t3.small"
  }
  # No aws:elasticbeanstalk:healthreporting:system / HealthStreamingEnabled setting
}
```

## Remediated example
```hcl
resource "aws_elastic_beanstalk_environment" "example" {
  name                = "example-env"
  application         = aws_elastic_beanstalk_application.example.name
  solution_stack_name = "64bit Amazon Linux 2 v5.8.0 running Node.js 18"

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "InstanceType"
    value     = "t3.small"
  }

  setting {
    namespace = "aws:elasticbeanstalk:healthreporting:system"
    name      = "SystemType"
    value     = "enhanced"                 # enable enhanced health reporting
  }

  setting {
    namespace = "aws:elasticbeanstalk:healthreporting:system"
    name      = "HealthStreamingEnabled"
    value     = "true"                     # stream enhanced health data to CloudWatch Logs
  }
}
```

## Remediation steps
1. Add a `setting` block with `namespace = "aws:elasticbeanstalk:healthreporting:system"`, `name = "SystemType"`, `value = "enhanced"` to switch from basic to enhanced health reporting.
2. Add a second `setting` block in the same namespace with `name = "HealthStreamingEnabled"`, `value = "true"` so Checkov's specific check passes and health logs stream to CloudWatch Logs.
3. Optionally set `HealthStreamingLogGroupRetentionInDays` and `DeleteOnTerminate` in the same namespace to control log retention.
4. Verify the environment's instance profile has permission to write to CloudWatch Logs.
5. This is a configuration update applied via environment update — it does not require replacing the environment, but Beanstalk will perform a rolling configuration update.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticBeanstalkUseEnhancedHealthChecks.py
- AWS docs: https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/health-enhanced.html
