# CKV_TC_5: Ensure Tencent Cloud CVM instances do not use the default VPC

## Severity
**MEDIUM** (score: 4.5/10)

Placing instances in the default VPC forgoes network segmentation from other workloads, increasing lateral-movement blast radius in the event of a compromise, but is not itself an externally exploitable exposure.

## Summary
This check ensures that Tencent Cloud CVM instances are placed in a purpose-built VPC/subnet rather than the account's default VPC or subnet.

## Applicability
**Checkov framework(s):** `terraform`

Terraform, resource type `tencentcloud_instance` (Tencent Cloud provider).

## Why it matters
The default VPC in a cloud account is typically pre-provisioned with permissive defaults intended to make first-time usage frictionless — often flatter network segmentation, broader default routing, and shared default security groups. Production workloads placed in the default VPC inherit whatever ad hoc changes other teams or test resources make to that shared network over time, and lack the deliberate segmentation (public/private subnet separation, per-environment isolation, controlled peering) that a custom VPC design provides. Using a custom VPC/subnet lets an organization enforce network segmentation between environments (prod/staging/dev) and application tiers, reducing the blast radius if one segment is compromised and making network architecture intentional and auditable rather than incidental.

## How Checkov evaluates this
This is a `BaseResourceCheck` that inspects the `vpc_id` and `subnet_id` attributes of a `tencentcloud_instance`. If either value contains the substring `.default.` (Checkov's convention for detecting a reference to a resource named/tagged as the default VPC or subnet), the check **FAILS**. If neither attribute references a default-named VPC/subnet, the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_instance" "app" {
  instance_name     = "app-server"
  availability_zone = "ap-guangzhou-3"
  image_id          = "img-9qabwvbn"
  instance_type     = "S5.MEDIUM4"
  vpc_id            = tencentcloud_vpc.default.id
  subnet_id         = tencentcloud_subnet.default.id
}

resource "tencentcloud_vpc" "default" {
  name       = "default"
  cidr_block = "10.0.0.0/16"
}
```

## Remediated example
```hcl
resource "tencentcloud_instance" "app" {
  instance_name     = "app-server"
  availability_zone = "ap-guangzhou-3"
  image_id          = "img-9qabwvbn"
  instance_type     = "S5.MEDIUM4"
  vpc_id            = tencentcloud_vpc.app_vpc.id
  subnet_id         = tencentcloud_subnet.app_private_subnet.id
}

resource "tencentcloud_vpc" "app_vpc" {
  name       = "app-vpc"
  cidr_block = "10.10.0.0/16"
}

resource "tencentcloud_subnet" "app_private_subnet" {
  name              = "app-private-subnet"
  vpc_id            = tencentcloud_vpc.app_vpc.id
  cidr_block        = "10.10.1.0/24"
  availability_zone = "ap-guangzhou-3"
}
```

## Remediation steps
1. Create a dedicated `tencentcloud_vpc` and `tencentcloud_subnet` for the workload (or environment) rather than reusing the account's default network resources.
2. Update `vpc_id` and `subnet_id` on the `tencentcloud_instance` to reference the new custom network resources.
3. Design subnetting deliberately: separate public and private subnets, and separate environments/tiers into distinct VPCs or subnets with controlled peering/routing between them.
4. Migrating an existing instance out of the default VPC generally requires recreating the instance in the new network (instances cannot be moved between VPCs in place) — plan for a maintenance window and data/config migration.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CVMUseDefaultVPC.py
