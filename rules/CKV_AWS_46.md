# CKV_AWS_46: Ensure no hard-coded secrets exist in EC2 user data
## Severity
**CRITICAL** (score: 9.0/10)

Hard-coded secrets in EC2 user data are retrievable in plaintext via the instance metadata service by anyone with access to the instance, making this an exposed-credential class finding.

## Summary
This check scans the `user_data` (bootstrap script) of EC2 instances, launch templates, and launch configurations for values that look like hard-coded secrets.

## Applicability
- **Frameworks:** CloudFormation, Terraform
- **Resource types:** `AWS::EC2::Instance` (CloudFormation); `aws_instance`, `aws_launch_template`, `aws_launch_configuration` (Terraform) — specifically the `UserData`/`user_data` attribute.

## Why it matters
EC2 user data is readable by anyone who can call the EC2 instance metadata service from within the instance (`http://169.254.169.254/latest/user-data`), by anyone with `ec2:DescribeInstanceAttribute` IAM permission, and is stored in plaintext in the instance's launch configuration/template — including in Terraform state and IaC source. User data scripts are commonly used to bootstrap software (install packages, configure services, join a cluster), and it's tempting to embed a database password, API key, or join token directly in the script for convenience. If an attacker gains even limited access to the instance (e.g., via SSRF against the metadata endpoint, a compromised low-privilege process, or console/API read access), any secret embedded in user data is immediately exposed — this has been a repeated real-world SSRF-to-credential-theft attack pattern.

## How Checkov evaluates this
Both implementations are `BaseResourceCheck`s:
- **CloudFormation:** reads `Properties/UserData`. Since CloudFormation user data is often base64-encoded, the check first attempts to base64-decode it; if that fails, it falls back to treating it as a raw string. It then runs the secret-detection heuristic (`get_secrets_from_string`, matching general and AWS credential patterns) on the resulting string. Any match → **FAIL**.
- **Terraform:** reads the `user_data` argument as a string and runs `string_has_secrets` (AWS-specific pattern matching) directly on it. Any match → **FAIL**.
- No secret-like content found (or no `user_data`/`UserData` set) → **PASS**.

## Non-compliant example
```hcl
resource "aws_instance" "example" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="Sup3rSecretPassw0rd!"
    /opt/app/start.sh
  EOF
}
```

## Remediated example
```hcl
resource "aws_instance" "example" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.app.name

  user_data = <<-EOF
    #!/bin/bash
    DB_PASSWORD=$(aws secretsmanager get-secret-value \
      --secret-id prod/app/db-password --query SecretString --output text)
    export DB_PASSWORD
    /opt/app/start.sh
  EOF
}
```

## Remediation steps
1. Remove any literal secret values from `user_data` scripts.
2. Fetch secrets at boot time from AWS Secrets Manager or SSM Parameter Store (SecureString) using the instance's IAM role, instead of embedding them in the script text.
3. Attach an `iam_instance_profile` with least-privilege access to only the specific secret(s) the instance needs.
4. If a real secret was committed this way, rotate it — user data is also visible in Terraform state files and CloudTrail/console history, so removal from the script alone is not sufficient remediation.
5. Consider using cloud-init's support for fetching secrets, or a configuration-management tool (e.g., AWS Systems Manager Run Command) that pulls secrets just-in-time rather than embedding them at instance launch.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EC2Credentials.py)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/EC2Credentials.py)
- [AWS EC2 instance metadata and user data documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
