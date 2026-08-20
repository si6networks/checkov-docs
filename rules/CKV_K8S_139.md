# CKV_K8S_139: Ensure that the --authorization-mode argument is not set to AlwaysAllow
## Severity
**LOW** (score: 2.0/10)

Setting the kubelet's --authorization-mode to AlwaysAllow disables authorization entirely, letting any request reach the kubelet API and execute commands or exfiltrate pod data on the node.

## Summary
This check ensures that the kubelet's `--authorization-mode` argument does not include the value `AlwaysAllow`, which would let any request to the kubelet API bypass authorization entirely.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests (and manifest-generating Terraform via Kubernetes provider resources indirectly, though this specific check is implemented only for native Kubernetes manifests) — specifically Pod-template-bearing workload kinds: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the `command` array of any container in the pod spec, and only acts when that command invokes `kubelet` (i.e., this targets kubelet static-pod manifests or kubelet-wrapper containers, not arbitrary application pods).

## Why it matters
The kubelet exposes an HTTPS API (default port 10250) used for exec/attach/logs/portforward and other node-management operations. If `--authorization-mode` is set to `AlwaysAllow` (or includes it in a comma-separated list), the kubelet performs no authorization check at all — any request that reaches the kubelet API, from any principal who can reach the port, is permitted regardless of RBAC. Combined with weak or no authentication, this can let an attacker who obtains network access to a node execute arbitrary commands inside any pod on that node, read pod logs and secrets mounted as files, or exfiltrate data — effectively a full node/cluster compromise. Kubernetes and the CIS Kubernetes Benchmark (control 4.2.1/4.2.2 depending on version) mandate `Webhook` (or another RBAC-integrated) mode instead, so kubelet requests are authorized against the same RBAC policy as the rest of the cluster.

## How Checkov evaluates this
The check (`KubeletAuthorizationModeNotAlwaysAllow`, a `BaseK8sContainerCheck`) inspects each container's `command` list:
1. If `command` is present and contains the string `kubelet`, it iterates the command-line arguments.
2. It looks for an argument starting with `--authorization-mode`, splits on `=`, and splits the value on `,` to get the list of configured modes.
3. If `AlwaysAllow` appears in that list, the check **FAILS**.
4. Otherwise (mode not set, or set without `AlwaysAllow`), the check **PASSES**.
Note: if `command` doesn't invoke kubelet at all, the check trivially passes (not applicable).

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
        - --authorization-mode=AlwaysAllow
        - --client-ca-file=/etc/kubernetes/pki/ca.crt
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
        - --authorization-mode=Webhook
        - --client-ca-file=/etc/kubernetes/pki/ca.crt
```

## Remediation steps
1. Locate the kubelet configuration — this is usually set via the `KubeletConfiguration` file (`/var/lib/kubelet/config.yaml`, key `authorization.mode`) rather than command-line flags on managed clusters, but self-managed/static-pod kubelet invocations pass it directly as `--authorization-mode`.
2. Change the value to `Webhook` (delegates authorization decisions to the API server, which applies normal RBAC) or a list that does not include `AlwaysAllow`.
3. Ensure the API server's `--authorization-mode` includes `Node` and `RBAC` so the webhook path has policy to evaluate against.
4. Restart the kubelet (and any static pod manager) to apply the change; this is a node-level, potentially disruptive change — plan a maintenance window per node.
5. On managed Kubernetes (EKS, GKE, AKS), the control plane and kubelet auth mode are typically managed by the provider and not directly configurable — this check mainly matters for self-managed/on-prem clusters and CIS benchmark compliance scans.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletAuthorizationModeNotAlwaysAllow.py
