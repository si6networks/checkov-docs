# CKV_AWS_339: Ensure EKS clusters run on a supported Kubernetes version
## Severity
**HIGH** (score: 7.5/10)

Running an EKS cluster on an unsupported Kubernetes version means it no longer receives security patches from AWS, leaving known control-plane and kubelet vulnerabilities unaddressed on infrastructure that hosts workload orchestration and secrets.

## Summary
This check requires that `aws_eks_cluster` resources set `version` to one of the Kubernetes releases AWS currently supports on EKS (at the time this check was authored: 1.29 through 1.35).

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_eks_cluster`
- **Note:** If `version` is omitted entirely, the check **passes** (`missing_block_result=CheckResult.PASSED`), since EKS will provision the cluster on its current default supported version.

## Why it matters
Kubernetes and EKS have a defined support lifecycle: once a minor version passes its standard support end date, AWS moves it into "extended support" (at extra cost) and eventually deprecates it entirely, at which point it no longer receives security patches for known CVEs in the control plane, kubelet, or other cluster components. Running an unsupported or soon-to-be-unsupported Kubernetes version means the cluster is not receiving fixes for newly discovered vulnerabilities in core Kubernetes components (API server, scheduler, controller-manager, etc.), leaving known, disclosed vulnerabilities unpatched indefinitely. It also tends to correlate with clusters that have drifted out of routine maintenance more broadly (stale add-ons, unpatched worker nodes), increasing overall operational and security risk.

## How Checkov evaluates this
The check (`EKSPlatformVersion.py`) is a `BaseResourceValueCheck`:
- It inspects the `version` attribute against an explicit allow-list: `["1.29", "1.30", "1.31", "1.32", "1.33", "1.34", "1.35"]`.
- If `version` is set to a value in that list, the check **PASSES**.
- If `version` is set to anything else (e.g., an older, deprecated version like `1.24`), the check **FAILS**.
- If `version` is omitted entirely, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) since EKS defaults to a currently-supported version.

**Important:** this allow-list is hardcoded in the Checkov source and reflects the versions supported as of that Checkov release. As EKS support windows advance, this check must be validated against the current Checkov version and AWS's up-to-date EKS Kubernetes version support table — a "PASSED" result from an outdated Checkov version may not reflect current AWS support status.

## Non-compliant example
```hcl
resource "aws_eks_cluster" "bad_example" {
  name     = "app-cluster"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.24"

  vpc_config {
    subnet_ids = var.subnet_ids
  }
}
```

## Remediated example
```hcl
resource "aws_eks_cluster" "good_example" {
  name     = "app-cluster"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.31"

  vpc_config {
    subnet_ids = var.subnet_ids
  }
}
```

## Remediation steps
1. Update `version` to a currently-supported EKS Kubernetes version — check the AWS EKS documentation for the current support table rather than relying solely on this check's hardcoded list, as it may lag behind AWS's actual release schedule.
2. Before upgrading, review the Kubernetes/EKS release notes for API deprecations that may affect your workloads (e.g., removed API versions for Ingress, PodSecurityPolicy, etc.) and update manifests accordingly.
3. Upgrade EKS clusters one minor version at a time — you cannot skip versions — and upgrade the control plane before upgrading managed node groups/Fargate profiles to matching versions.
4. Plan for a maintenance window: control plane upgrades are managed by AWS and generally low-risk, but validate application compatibility and run the upgrade through a staging cluster first.
5. Also upgrade cluster add-ons (CoreDNS, kube-proxy, VPC CNI) to versions compatible with the new Kubernetes version, as EKS does not always do this automatically.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EKSPlatformVersion.py)
- [AWS: Amazon EKS Kubernetes versions](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html)
