# CKV_AWS_39: Ensure Amazon EKS public endpoint disabled

## Severity
**HIGH** (score: 7.5/10)

Enabling any public endpoint access on the EKS API server (even with CIDR filtering elsewhere) broadens the attack surface of the Kubernetes control plane to the internet, a sensitive management interface that should default to private-only access.

## Summary
This check ensures the EKS cluster's Kubernetes API server public endpoint is fully disabled (`endpoint_public_access = false`), rather than merely restricted to specific CIDRs.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_eks_cluster`

## Why it matters
The EKS control plane API server endpoint is the entry point for all cluster administration (`kubectl`, CI/CD deployment tooling, cluster-autoscaler, etc.). Enabling `endpoint_public_access` at all — even with CIDR restrictions in place (see CKV_AWS_38) — means the API server is reachable over the public internet:

- It becomes a target for internet-wide scanning and probing against the Kubernetes API, which has historically had vulnerabilities in authentication/authorization edge cases, admission controllers, and API server bugs.
- Even correctly-restricted CIDR access can be defeated by IP spoofing in some network paths, misconfiguration drift over time, or if the "trusted" source ranges themselves become compromised (e.g., a corporate VPN egress IP that gets compromised).
- The strongest posture is no public exposure at all: `endpoint_public_access = false` with `endpoint_private_access = true`, so the API server is reachable only from within the VPC (via VPN, Direct Connect, a bastion, or a peered/transit-gateway-connected network) — eliminating the public internet as an attack vector for the control plane entirely.

This check is stricter than CKV_AWS_38: it doesn't accept a merely-restricted CIDR list, it wants the public endpoint switched off entirely.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` inspecting the attribute path:

```
vpc_config/[0]/endpoint_public_access
```

The expected value is `False`. The check **PASSES** only when `endpoint_public_access` is explicitly set to `false`. If it is `true`, or the attribute/`vpc_config` block is missing (which defaults to `true` in the AWS provider for `aws_eks_cluster`), the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_eks_cluster" "example" {
  name     = "example-cluster"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids            = [aws_subnet.a.id, aws_subnet.b.id]
    endpoint_public_access = true
  }
}
```

## Remediated example
```hcl
resource "aws_eks_cluster" "example" {
  name     = "example-cluster"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids             = [aws_subnet.a.id, aws_subnet.b.id]
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}
```

## Remediation steps
1. Set `endpoint_public_access = false` in the `vpc_config` block.
2. Set `endpoint_private_access = true` so the API server remains reachable from within the VPC.
3. Ensure your CI/CD runners, `kubectl` users, and any automation that talks to the cluster API have network connectivity to the VPC (via VPN, Direct Connect, a bastion host/jump box in the VPC, or a peered network) — this is the main operational tradeoff of full private access.
4. If a temporary public endpoint is unavoidable for a specific migration/bootstrap task, restrict it tightly with `public_access_cidrs` (see CKV_AWS_38) and disable it again immediately afterward.
5. This is an in-place cluster update but can take several minutes to propagate through the EKS control plane; plan around a maintenance window and verify connectivity from your private access path before disabling public access, to avoid locking yourself out.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EKSPublicAccess.py)
- [Amazon EKS cluster endpoint access control documentation](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html)
