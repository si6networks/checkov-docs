# CKV_AWS_340: Ensure Elastic Beanstalk managed platform updates are enabled
## Severity
**LOW** (score: 2.0/10)

Disabling Elastic Beanstalk managed platform updates prevents automatic application of AWS security patches to the underlying platform, gradually increasing exposure to known vulnerabilities in the managed runtime and OS layer.

## Summary
This check requires that `aws_elastic_beanstalk_environment` resources configure the `aws:elasticbeanstalk:managedactions` namespace's `ManagedActionsEnabled` setting to `true`, so the environment automatically applies platform updates.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_elastic_beanstalk_environment`

## Why it matters
Elastic Beanstalk regularly releases new platform versions that bundle security patches for the underlying OS, language runtime, web server, and other managed components (e.g., Amazon Linux updates, Node.js/Python/Java runtime patches). If managed platform updates are disabled, an environment stays pinned to whatever platform version it was created with (or last manually updated to) indefinitely — meaning it continues running with any subsequently disclosed and patched vulnerabilities in that platform stack. Since Elastic Beanstalk abstracts away the underlying instances, teams frequently "set and forget" these environments, making automatic managed updates one of the few reliable ways to ensure the platform layer doesn't silently accumulate unpatched CVEs over time.

## How Checkov evaluates this
The check (`ElasticBeanstalkUseManagedUpdates.py`) walks the `setting` blocks on the resource:
1. Looks for a `setting` entry where `namespace == "aws:elasticbeanstalk:managedactions"`.
2. Within that entry, looks for `name == "ManagedActionsEnabled"`.
3. If that setting's `value` is `"True"` (string) or any truthy boolean, the check **PASSES**.
4. If no such setting exists, or its value is falsy/`"False"`, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_elastic_beanstalk_environment" "bad_example" {
  name                = "app-env"
  application         = aws_elastic_beanstalk_application.app.name
  solution_stack_name = "64bit Amazon Linux 2023 v4.1.0 running Python 3.12"

  # No managed platform updates setting -> defaults to disabled
}
```

## Remediated example
```hcl
resource "aws_elastic_beanstalk_environment" "good_example" {
  name                = "app-env"
  application         = aws_elastic_beanstalk_application.app.name
  solution_stack_name = "64bit Amazon Linux 2023 v4.1.0 running Python 3.12"

  setting {
    namespace = "aws:elasticbeanstalk:managedactions"
    name      = "ManagedActionsEnabled"
    value     = "true"
  }

  setting {
    namespace = "aws:elasticbeanstalk:managedactions"
    name      = "PreferredStartTime"
    value     = "Sun:03:00"
  }

  setting {
    namespace = "aws:elasticbeanstalk:managedactions:platformupdate"
    name      = "UpdateLevel"
    value     = "minor"
  }
}
```

## Remediation steps
1. Add a `setting` block with `namespace = "aws:elasticbeanstalk:managedactions"`, `name = "ManagedActionsEnabled"`, `value = "true"`.
2. Set `PreferredStartTime` (under the same namespace) to a low-traffic maintenance window, since managed updates can restart environment instances.
3. Configure `aws:elasticbeanstalk:managedactions:platformupdate` → `UpdateLevel` to `minor` (recommended: patch + minor version updates, avoiding potentially breaking major version jumps) and optionally `InstanceRefreshEnabled` to ensure instances are refreshed as part of the update.
4. Test in a staging environment first if you're enabling this on a previously unmanaged environment — an accumulated backlog of updates could trigger a larger jump than expected on first run.
5. This is a non-disruptive configuration setting change (no environment replacement needed), but actual managed update executions will cause a rolling instance replacement during the configured maintenance window.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticBeanstalkUseManagedUpdates.py)
- [AWS: Managed platform updates for Elastic Beanstalk environments](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environment-platform-update-managed.html)
