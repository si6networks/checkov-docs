# CKV_K8S_145: Ensure that the --make-iptables-util-chains argument is set to true
## Severity
**LOW** (score: 2.0/10)

The --make-iptables-util-chains setting governs whether kubelet manages helper iptables chains for correct traffic accounting, an operational/networking hygiene control with no direct confidentiality or integrity exploit path.

## Summary
This check ensures the kubelet is started with `--make-iptables-util-chains=true`, so it manages its own iptables utility chains rather than relying on manual/external configuration.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting when it invokes `kubelet`.

## Why it matters
`--make-iptables-util-chains=true` lets the kubelet create and maintain the iptables utility chains it needs for its own operation and for consistent interaction with kube-proxy's networking rules, rather than depending on the node administrator to have set these up manually and keep them correct over time. When left disabled or unmanaged, iptables rules can drift, be misconfigured, or be inconsistent across nodes, leading to unpredictable network policy enforcement, service routing failures, or gaps in traffic filtering that a security-relevant iptables rule was meant to close. This is a defense-in-depth / configuration-consistency control from CIS Kubernetes Benchmark 4.2.7, ensuring the kubelet's networking prerequisites are reliably self-managed instead of relying on fragile manual node setup that could unintentionally leave the node's firewall rules in an insecure or inconsistent state.

## How Checkov evaluates this
The check (`KubeletMakeIptablesUtilChains`) looks at each container's `command` list:
1. If `kubelet` is among the command tokens, it checks whether the exact string `--make-iptables-util-chains=true` is present in the command list.
2. If that exact flag/value is **not** present (absent, `false`, or different formatting), the check **FAILS**.
3. If present, the check **PASSES**.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-static-pod
spec:
  containers:
    - name: kubelet
      image: k8s.gcr.io/hyperkube:v1.20.0
      command:
        - kubelet
        - --make-iptables-util-chains=false
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-static-pod
spec:
  containers:
    - name: kubelet
      image: k8s.gcr.io/hyperkube:v1.20.0
      command:
        - kubelet
        - --make-iptables-util-chains=true
```

## Remediation steps
1. Add `--make-iptables-util-chains=true` to the kubelet command line, or set `makeIPTablesUtilChains: true` in the `KubeletConfiguration` file.
2. If this flag was previously set to `false` intentionally (e.g., a custom network setup managing its own iptables rules), verify no conflicting manual iptables management exists on the node before flipping it back to `true`.
3. Roll out per node and confirm kube-proxy and pod networking continue to function correctly after the kubelet restarts.
4. This flag is deprecated in newer Kubernetes versions in favor of always-on behavior; check your kubelet version's release notes if the flag is no longer recognized.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletMakeIptablesUtilChains.py
