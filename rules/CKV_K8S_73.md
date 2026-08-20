# CKV_K8S_73: Ensure that the --kubelet-certificate-authority argument is set as appropriate
## Severity
**HIGH** (score: 7.5/10)

Without a configured kubelet certificate authority the API server cannot validate kubelet server certificates, allowing an on-path attacker to impersonate a kubelet during API-server-to-node connections.

## Summary
This check fails a `kube-apiserver` container manifest unless its `command` includes the `--kubelet-certificate-authority` argument, which the API server uses to validate the TLS certificate presented by kubelets it connects to.

## Applicability
Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
Without `--kubelet-certificate-authority` configured, the API server has no trust anchor to validate kubelet server certificates, forcing it to either fail closed or (in many configurations) skip verification of the kubelet's TLS certificate when connecting for exec/logs/port-forward/metrics operations. This exposes the control plane to man-in-the-middle attacks: an attacker who can position themselves on the network path to a node (e.g., via ARP spoofing inside the cluster network, or a rogue node joining the cluster) could impersonate a kubelet and intercept or tamper with API-server-to-kubelet traffic, including exec sessions that may carry sensitive data. This is CIS Kubernetes Benchmark 1.2.10 / 1.2.11 depending on version, and complements CKV_K8S_72 (client cert/key) and CKV_K8S_71 (HTTPS enforced) to form full mutual-TLS validation.

## How Checkov evaluates this
`ApiServerkubeletCertificateAuthority.py` uses a shared `extract_commands` helper to split `command` tokens into `keys` (flag names) and `values`. It fails if `"kube-apiserver"` is present in `keys` but `"--kubelet-certificate-authority"` is **not** present among the extracted flag keys. If the container doesn't run `kube-apiserver`, it passes.

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
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --etcd-servers=https://127.0.0.1:2379
    - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
    - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
    # --kubelet-certificate-authority missing -> FAILS
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
    - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
    - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
    - --kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt
```

## Remediation steps
1. Identify (or generate, for kubeadm-managed clusters this is auto-created) the CA certificate that signs kubelet serving certificates.
2. Add `--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt` (or the correct path) to the `kube-apiserver` command.
3. Ensure kubelets are actually serving certificates signed by that CA (kubelet `--tls-cert-file`/`--tls-private-key-file`, or automatic self-signed cert rotation via `--rotate-certificates` bootstrapped against the same CA).
4. Restart the API server and confirm `kubectl top nodes`, `kubectl logs`, and `kubectl exec` still succeed (these all traverse the API-server-to-kubelet path).
5. Re-scan with `checkov -d . --check CKV_K8S_73`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerkubeletCertificateAuthority.py)
- [Kubernetes kube-apiserver reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
