# CKV_K8S_71: Ensure that the --kubelet-https argument is set to true
## Severity
**HIGH** (score: 7.5/10)

Disabling kubelet HTTPS causes API server-to-kubelet traffic (including exec/logs/port-forward) to travel unencrypted and unauthenticated, exposing it to interception and man-in-the-middle tampering.

## Summary
This check fails a `kube-apiserver` container manifest if its `command` explicitly sets `--kubelet-https=false`, which would force the API server to talk to kubelets over plaintext HTTP instead of TLS.

## Applicability
Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
The API server communicates with kubelets on each node for operations like `kubectl logs`, `kubectl exec`, and metrics collection. `--kubelet-https` controls whether this communication uses TLS. If set to `false`, all traffic between the API server and kubelets (which can include exec/attach session data, environment info, and logs — sometimes containing secrets) travels in cleartext over the node network, exposing it to any attacker with network visibility (e.g., via ARP spoofing, a compromised node, or a misconfigured overlay network) to eavesdrop or tamper with control-plane-to-kubelet traffic. This is CIS Kubernetes Benchmark 1.2.8 (older CIS versions). The flag itself is deprecated/removed in modern Kubernetes (HTTPS is now the only mode), so its explicit presence set to `false` is a strong signal of a misconfigured or very old cluster.

## How Checkov evaluates this
`ApiServerKubeletHttps.py`: if the container's `command` contains `"kube-apiserver"`, the check fails **only** if the exact string `"--kubelet-https=false"` appears in `command`. If the flag is absent entirely, or set to any other value, it passes (the check does not require the flag to be present — it only rejects the explicit `false` value).

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.20.0
    command:
    - kube-apiserver
    - --etcd-servers=https://127.0.0.1:2379
    - --kubelet-https=false   # plaintext kubelet comms -> FAILS
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --etcd-servers=https://127.0.0.1:2379
    # --kubelet-https removed/left default (true) -> TLS enforced
```

## Remediation steps
1. Remove `--kubelet-https=false` entirely, or set it to `true`, from the `kube-apiserver` command.
2. Ensure kubelets are configured with valid TLS serving certificates (`--tls-cert-file`/`--tls-private-key-file` on the kubelet, or use kubelet's built-in self-signed cert bootstrap) so the API server can establish HTTPS connections successfully.
3. Configure `--kubelet-certificate-authority` on the API server to validate kubelet certificates rather than skipping verification (see CKV_K8S_73).
4. Upgrade to a supported Kubernetes version if you're relying on this deprecated flag at all — modern releases removed insecure HTTP kubelet communication entirely.
5. Re-scan with `checkov -d . --check CKV_K8S_71`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerKubeletHttps.py)
- [Kubernetes kube-apiserver reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
