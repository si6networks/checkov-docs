# CKV_K8S_89: Ensure that the --secure-port argument is not set to 0
## Severity
**HIGH** (score: 8.0/10)

Setting the secure port to 0 disables the authenticated, TLS-protected API server endpoint entirely, removing the primary control-plane access path and its associated authentication/authorization checks.

## Summary
This check verifies that a self-managed `kube-apiserver` container does not disable its authenticated, TLS-secured HTTPS listener by setting `--secure-port=0`.

## Applicability
Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
The secure port is the API server's TLS-encrypted, authenticated/authorized HTTPS endpoint — it is the primary, correct way clients and components should talk to the cluster. Setting `--secure-port=0` disables this endpoint entirely. If the insecure port is still active (older clusters) or some other mechanism is providing access, disabling the secure port removes TLS encryption and the authentication/authorization/admission control pipeline from that access path, which is the opposite of the hardening goal — it either breaks the cluster (no authenticated access at all) or, worse, forces reliance on the plaintext insecure port as the only way in, exposing the API completely.

## How Checkov evaluates this
The check (`ApiServerSecurePort`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is not a list, or doesn't contain `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it FAILS if and only if the literal string `--secure-port=0` appears in the command list.
3. If `--secure-port` is absent entirely, or set to any non-zero value, or set via a separate `--secure-port 6443`-style pair (not joined with `=`), the check returns PASSED — it only detects the specific `--secure-port=0` string.

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
        - --secure-port=0
        - --insecure-port=8080
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
        - --secure-port=6443
        - --etcd-servers=https://127.0.0.1:2379
```

## Remediation steps
1. Remove any `--secure-port=0` argument from the `kube-apiserver` command, or set it to the standard port (default 6443).
2. If the flag is entirely absent, no action is required — `kube-apiserver` defaults to `--secure-port=6443`.
3. Confirm firewall/security-group rules allow inbound traffic to the secure port from expected clients (nodes, kubectl users, controllers) and that the insecure port (if present on older clusters) is disabled per CKV_K8S_88.
4. Restart/verify the static pod picks up the change (kubelet auto-restarts static pods on manifest change) and confirm connectivity: `kubectl get --raw='/healthz'` against the secure endpoint.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerSecurePort.py)
- [Kubernetes API server options reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
