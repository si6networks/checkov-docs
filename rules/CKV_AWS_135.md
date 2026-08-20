# CKV_AWS_135: Ensure that EC2 is EBS optimized

## Severity
**LOW** (score: 2.0/10)

EBS optimization affects dedicated I/O throughput/performance for EC2 instances and has no confidentiality, integrity, or access-control implication.

## Summary
This check requires EC2 instances to enable EBS optimization (`ebs_optimized = true`) so the instance gets dedicated, consistent throughput to its attached EBS volumes rather than sharing general network bandwidth with other traffic.

## Applicability
**Checkov framework(s):** `ansible`, `terraform`

- **Frameworks:** Terraform (AWS provider), Ansible
- **Resource/task types:**
  - Terraform: `aws_instance`
  - Ansible: tasks using the `amazon.aws.ec2_instance` or `ec2_instance` modules (only evaluated when `image_id`/`image` is set, since a task without an image is targeting an already-running instance rather than launching a new one, in which case the result is UNKNOWN)

## Why it matters
This check is classified under general/reliability security rather than confidentiality, but it has real availability and integrity implications: without EBS optimization, storage I/O contends with other network traffic on the instance's shared network interface. Under load (e.g., a burst of legitimate traffic, or an active denial-of-service condition), disk I/O can be starved, causing application slowdowns, timeouts, or failed writes — which can look like or contribute to an availability incident, and can also mask or worsen the effects of an actual attack that already saturates network bandwidth. For any workload where storage latency/throughput matters (databases, log-heavy applications, anything doing significant disk I/O), lacking EBS optimization creates an unpredictable, contention-prone performance profile. Note that most current-generation instance types have this dedicated bandwidth enabled by default and enabling it explicitly on older/smaller instance types has no extra cost on newer generations.

## How Checkov evaluates this
**Terraform** (`BaseResourceValueCheck`):
- Inspects the `ebs_optimized` attribute on `aws_instance`.
- **PASS** if `ebs_optimized = true`; **FAIL** if `false` or absent.

**Ansible** (`BaseAnsibleTaskValueCheck`):
- Applies to tasks calling `amazon.aws.ec2_instance` or `ec2_instance`.
- If the task does not set `image_id` or `image`, it is presumed to be managing an already-existing instance (not launching a new one) — result is **UNKNOWN**.
- Otherwise inspects the `ebs_optimized` key the same way: **PASS** if truthy, **FAIL** otherwise.

## Non-compliant example
```hcl
resource "aws_instance" "app" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "m5.large"
  # ebs_optimized not set -> FAIL
}
```

```yaml
- name: Launch app instance
  amazon.aws.ec2_instance:
    name: app-instance
    image_id: ami-0c55b159cbfafe1f0
    instance_type: m5.large
    # ebs_optimized not set -> FAIL
```

## Remediated example
```hcl
resource "aws_instance" "app" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "m5.large"
  ebs_optimized = true   # added
}
```

```yaml
- name: Launch app instance
  amazon.aws.ec2_instance:
    name: app-instance
    image_id: ami-0c55b159cbfafe1f0
    instance_type: m5.large
    ebs_optimized: true   # added
```

## Remediation steps
1. Add `ebs_optimized = true` (Terraform) or `ebs_optimized: true` (Ansible) to the instance definition.
2. Verify the chosen instance type supports EBS optimization — most current-generation types (M5, C5, R5, T3, etc.) are EBS-optimized by default at no extra cost; a small number of older/smaller instance types either don't support it or incur an additional hourly charge.
3. For Ansible tasks that manage existing instances (no `image`/`image_id`), this control doesn't apply at launch time — ensure EBS optimization was set when the instance was originally created, or modify the existing instance's attribute out of band.
4. Changing `ebs_optimized` on an existing running instance typically requires stopping and starting (not just rebooting) the instance, since it is an EC2 instance attribute that cannot be modified while running for all instance families — plan for a maintenance window.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EC2EBSOptimized.py)
- [Checkov check source (Ansible)](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/task/aws/EC2EBSOptimized.py)
- [AWS: Amazon EBS–optimized instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html)
