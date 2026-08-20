# CKV2_AWS_41: Ensure an IAM role is attached to EC2 instance
## Severity
**LOW** (score: 2.0/10)

Missing an IAM instance profile on an EC2 instance is an operational/hygiene gap (it often pushes teams toward embedding long-lived static credentials) rather than a directly exploitable misconfiguration in itself.

## Summary
This check fails when an `aws_instance` resource has no `iam_instance_profile` attribute set, meaning the EC2 instance has no IAM role attached.

## Applicability
- **IaC framework:** Terraform
- **Resource/entity types:** `aws_instance`

## Why it matters
Without an attached IAM instance profile, applications running on the instance have no supported way to obtain temporary, automatically-rotated AWS credentials from the EC2 metadata service. In practice this pushes developers toward embedding long-lived IAM access keys in application config, environment variables, user-data scripts, or baked into AMIs — all of which are far more likely to leak (via source control, logs, SSRF against the metadata endpoint, or a compromised host) and don't expire automatically. Long-lived static credentials are a leading cause of AWS account compromise; an attached role lets you grant only the specific, scoped, and revocable permissions the instance's workload needs, with credentials that rotate hourly and disappear when the instance terminates.

## How Checkov evaluates this
This is a graph-based JSON policy that inspects a single attribute:
- **Attribute checked:** `iam_instance_profile` on `aws_instance`
- **Operator:** `exists`
- **PASS** if `iam_instance_profile` is set to any value (an instance profile name or ARN reference).
- **FAIL** if the attribute is absent entirely. Note this only confirms *some* profile is attached — it does not evaluate whether the role behind that profile is itself over-permissive (that's covered by separate IAM policy checks).

## Non-compliant example
```hcl
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public.id
  # no iam_instance_profile set
}
```

## Remediated example
```hcl
resource "aws_iam_role" "web_role" {
  name = "web-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "web_profile" {
  name = "web-instance-profile"
  role = aws_iam_role.web_role.name
}

resource "aws_instance" "web" {
  ami                  = "ami-0c55b159cbfafe1f0"
  instance_type        = "t3.micro"
  subnet_id            = aws_subnet.public.id
  iam_instance_profile = aws_iam_instance_profile.web_profile.name
}
```

## Remediation steps
1. Create an `aws_iam_role` with an `assume_role_policy` trusting `ec2.amazonaws.com`.
2. Attach only the least-privilege policies the workload requires (avoid broad managed policies like `AdministratorAccess`).
3. Wrap the role in an `aws_iam_instance_profile`.
4. Reference the instance profile's name (or ARN) via `iam_instance_profile` on the `aws_instance` resource.
5. Attaching or changing an instance profile after launch is supported without replacement in most cases, but confirm workloads are updated to stop using any previously hardcoded static credentials, and rotate/deactivate those old keys once the role is in place.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/EC2InstanceHasIAMRoleAttached.json
- AWS docs: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html
