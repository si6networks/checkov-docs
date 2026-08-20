# CKV_K8S_72: Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate
## Severity
**HIGH** (score: 7.5/10)

Missing kubelet client certificate/key means the API server cannot mutually authenticate to kubelets over TLS, weakening the control-plane-to-node trust boundary and enabling spoofing or MITM against kubelet APIs.

## Summary
This check fails a `kube-apiserver` container manifest unless its `command` sets **both** `--kubelet-client-certificate` and `--kubelet-client-key`, which together let the API server authenticate itself to kubelets using mutual TLS.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests where a container's `command` runs `kube-apiserver`, evaluated across container-bearing kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — in practice, a self-managed/on-prem control-plane static pod manifest for `kube-apiserver`.

## Why it matters
By default, the kubelet's HTTPS endpoint can be configured to allow anonymous or unauthenticated requests, or to require client certificate authentication. When the API server presents a client certificate (via `--kubelet-client-certificate`/`--kubelet-client-key`), the kubelet can authenticate the caller as the API server identity and authorize the request (e.g. via webhook authorization against RBAC `nodes/proxy` subresource permissions), rather than trusting any caller that reaches its port. Without these flags configured, in kubelet configurations that permit it, requests to the kubelet API (exec, logs, port-forward, metrics) may not be properly attributable/authenticated, widening the attack surface for anyone with network access to node ports (10250) to interact with the kubelet impersonating the control plane. This is CIS Kubernetes Benchmark 1.2.9/1.2.10.

## How Checkov evaluates this
`ApiServerKubeletClientCertAndKey.py`: if the container's `command` contains `"kube-apiserver"`, it scans all command tokens and sets two booleans — `hasCertCommand` if any token starts with `--kubelet-client-certificate`, `hasKeyCommand` if any token starts with `--kubelet-client-key`. Result is PASSED only if **both** are true; otherwise FAILED. If the container isn't running `kube-apiserver`, it passes (not applicable).

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
    # kubelet client cert/key not configured -> FAILS
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
```

## Remediation steps
1. Generate (or use kubeadm's auto-generated) a client certificate/key pair for the API server to present to kubelets, typically issued by the cluster CA.
2. Add `--kubelet-client-certificate=<path>.crt` and `--kubelet-client-key=<path>.key` to the `kube-apiserver` command, pointing at that cert/key pair.
3. Ensure the kubelet's API is configured to require client certificate authentication (kubelet `--client-ca-file` pointing at the same CA that signed the API server's client cert).
4. Confirm the node authorizer/RBAC (`system:kube-apiserver` or `system:masters` binding as appropriate) permits the API server's client identity to reach kubelet endpoints.
5. Restart the API server static pod and verify `kubectl logs`/`kubectl exec` still function against a test pod.
6. Re-scan with `checkov -d . --check CKV_K8S_72`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerKubeletClientCertAndKey.py)
- [Kubernetes kube-apiserver reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [Kubernetes kubelet authentication/authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
