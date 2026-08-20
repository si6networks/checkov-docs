# CKV_AWS_38: Ensure Amazon EKS public endpoint not accessible to 0.0.0.0/0

## Severity
**LOW** (score: 2.0/10)

An EKS public API endpoint reachable from 0.0.0.0/0 exposes the Kubernetes control plane to the entire internet, making it a prime target for credential-stuffing or exploit attempts against the cluster's most sensitive management interface.

## Summary
This check ensures that when an EKS cluster's public API endpoint is enabled, it is not left open to the entire internet (`0.0.0.0/0`) via `public_access_cidrs`.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_eks_cluster`

## Why it matters
The EKS control-plane API server endpoint is how `kubectl` and other tooling communicate with the cluster. If the public endpoint is enabled (`endpoint_public_access = true`) and the allowed CIDR list includes `0.0.0.0/0`:

- Anyone on the internet can reach the Kubernetes API server network endpoint, turning what should be a defense-in-depth network boundary into no boundary at all.
- While IAM/RBAC authentication is still required to actually issue API calls, exposing the endpoint globally significantly increases the attack surface: it invites credential-stuffing/brute-force attempts, exposes the server to any unpatched TLS/HTTP-level vulnerabilities in the API server, and removes network-layer protection as a second line of defense if authentication is ever misconfigured or compromised.
- Combined with weak IAM policies or leaked kubeconfig credentials, an internet-reachable API server can be a direct path to full cluster compromise.

## How Checkov evaluates this
The check reads the `vpc_config` block of the `aws_eks_cluster` resource:

- If `endpoint_public_access` is present and evaluates to `false`, the check **PASSES** immediately (no public endpoint at all).
- Otherwise, if `public_access_cidrs` is present, it fails unless the CIDR list is non-empty and does **not** contain `"0.0.0.0/0"`.
- If neither condition is met (e.g., `vpc_config` exists but has no usable public-access settings to evaluate), the check **FAILS**.
- If `vpc_config` is missing entirely, the result is **UNKNOWN** (Checkov cannot determine public exposure without it).

## Non-compliant example
```hcl
resource "aws_eks_cluster" "example" {
  name     = "example-cluster"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = [aws_subnet.a.id, aws_subnet.b.id]
    endpoint_public_access   = true
    public_access_cidrs      = ["0.0.0.0/0"]
  }
}
```

## Remediated example
```hcl
resource "aws_eks_cluster" "example" {
  name     = "example-cluster"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = [aws_subnet.a.id, aws_subnet.b.id]
    endpoint_public_access   = true
    public_access_cidrs      = ["203.0.113.0/24"]
    endpoint_private_access  = true
  }
}
```

## Remediation steps
1. If the cluster does not need a public endpoint, set `endpoint_public_access = false` and rely on `endpoint_private_access = true` with VPN/Direct Connect/bastion access from within the VPC.
2. If public access is required (e.g., for CI/CD runners outside the VPC), restrict `public_access_cidrs` to the specific known IP ranges that need access — never `0.0.0.0/0`.
3. Enable `endpoint_private_access = true` alongside a restricted public endpoint so in-VPC traffic doesn't need to traverse the public endpoint at all.
4. Combine with EKS cluster security group rules and Kubernetes RBAC least privilege as additional layers.
5. Changing `vpc_config` public access settings updates the cluster in place; no full cluster replacement is required, but allow for a short reconciliation period.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EKSPublicAccessCIDR.py)
- [Amazon EKS cluster endpoint access control documentation](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html)
