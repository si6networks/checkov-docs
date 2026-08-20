# CKV_YC_5: Ensure Kubernetes cluster does not have public IP address.

## Severity
**CRITICAL** (score: 9.0/10)

Assigning a public IP to the Kubernetes master exposes the cluster's control-plane API server — the single most privileged management interface in the cluster — directly to the internet, removing network-layer defense-in-depth against credential theft and unpatched API-server vulnerabilities.

## Summary
This check ensures that a Yandex Managed Service for Kubernetes cluster's master (control plane) does not have a public IP address assigned, keeping the Kubernetes API server reachable only from private/internal networks.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `yandex_kubernetes_cluster`
- **Check type:** resource (negative value check)

## Why it matters
The Kubernetes API server is the control-plane endpoint that authenticates and authorizes every `kubectl` command, every controller reconciliation loop, and every CI/CD deployment against the cluster. If the master's `public_ip` is enabled, the API server endpoint becomes reachable from the public internet, dramatically expanding the attack surface: it becomes a target for credential-stuffing/brute-force attempts against exposed authentication endpoints, exploitation of unpatched Kubernetes API server CVEs, and reconnaissance scanning. Even with RBAC and TLS client-cert auth in place, a publicly reachable API server removes a critical layer of defense-in-depth — network-level isolation — meaning a leaked kubeconfig, a stolen service-account token, or an unpatched vulnerability becomes immediately exploitable from anywhere, rather than requiring the attacker to first gain a foothold inside the private network or VPN. Restricting the API server to private connectivity (accessed via VPN, bastion host, or peered private network) means attackers must first breach an internal network boundary before they can even attempt to interact with the cluster control plane.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the attribute path:
```
master/[0]/public_ip
```
If `public_ip` is set to `true` within the `master` block, the check **FAILS**. If it is absent, `false`, or any non-`true` value, the check **PASSES**.

## Non-compliant example
```hcl
resource "yandex_kubernetes_cluster" "bad_example" {
  name       = "prod-cluster"
  network_id = yandex_vpc_network.default.id

  master {
    version   = "1.28"
    public_ip = true

    zonal {
      zone      = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.default.id
    }
  }

  service_account_id      = yandex_iam_service_account.k8s.id
  node_service_account_id = yandex_iam_service_account.k8s_node.id
}
```

## Remediated example
```hcl
resource "yandex_kubernetes_cluster" "good_example" {
  name       = "prod-cluster"
  network_id = yandex_vpc_network.default.id

  master {
    version   = "1.28"
    # public_ip removed / explicitly false — API server stays on private connectivity
    public_ip = false

    zonal {
      zone      = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.default.id
    }
  }

  service_account_id      = yandex_iam_service_account.k8s.id
  node_service_account_id = yandex_iam_service_account.k8s_node.id
}
```

## Remediation steps
1. Set `public_ip = false` (or remove the attribute, since `false` is the default) in the `master` block of the `yandex_kubernetes_cluster` resource.
2. Ensure operators and CI/CD systems can still reach the private API endpoint — via a VPN gateway, bastion host, or a peered/private network route into the cluster's VPC.
3. If external access is truly required for specific automation, consider a bastion/jump host with strict security-group rules and audited access, rather than exposing the API server directly.
4. This change may require recreating the cluster's master public endpoint configuration; review the Terraform plan carefully as changing `public_ip` can affect master connectivity during apply.
5. Re-run Checkov to confirm `master.public_ip` is not `true`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/yandexcloud/K8SPublicIP.py
