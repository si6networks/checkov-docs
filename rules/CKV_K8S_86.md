# CKV_K8S_86: Ensure that the --insecure-bind-address argument is not set
## Severity
**CRITICAL** (score: 9.1/10)

Binding the API server to an insecure, unauthenticated HTTP address exposes full cluster control to anyone who can reach that address, equivalent to disabling authentication on the management plane.

## Summary
This check verifies that a self-managed `kube-apiserver` container does not use the removed/deprecated `--insecure-bind-address` flag, which would expose an unauthenticated, unencrypted API server listener.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
`--insecure-bind-address` (along with the related `--insecure-port`) historically caused the API server to serve a plaintext HTTP endpoint with no authentication or authorization applied at all — any process able to reach that address/port had full, unauthenticated read/write access to cluster state (secrets, RBAC objects, workloads). If bound to a non-localhost address, this insecure port could be exposed to the network, giving any attacker on the same network segment complete control of the cluster with zero credentials. This flag was deprecated in Kubernetes 1.10 and removed entirely in 1.20, but legacy manifests, ansible playbooks, or vendored kubeadm templates for older clusters can still set it.

## How Checkov evaluates this
The check (`ApiServerInsecureBindAddress`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is missing or doesn't include `kube-apiserver`, returns PASSED (not the API server).
2. If `kube-apiserver` is present, it strips the `=value` suffix off every argument to get just the flag names, and FAILS if `--insecure-bind-address` appears anywhere in that stripped list, regardless of what value (if any) was assigned to it.
3. Otherwise returns PASSED.

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
      image: registry.k8s.io/kube-apiserver:v1.18.0
      command:
        - kube-apiserver
        - --insecure-bind-address=0.0.0.0
        - --etcd-servers=https://127.0.0.1:2379
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
        # --insecure-bind-address removed entirely; only the secure,
        # authenticated HTTPS listener (--bind-address / --secure-port) is used
```

## Remediation steps
1. Remove the `--insecure-bind-address` argument entirely from the `kube-apiserver` command/args — do not just change its value.
2. Ensure `--secure-port` is set to a non-zero value (default 6443) so clients connect only via the authenticated/encrypted endpoint.
3. If you are running a Kubernetes version >= 1.20, this flag no longer exists in the binary at all and specifying it will cause `kube-apiserver` to fail to start — treat any occurrence in your manifests as leftover cruft from an old template that must be deleted.
4. Rotate any client configuration (`kubectl` contexts, in-cluster clients) that may have been pointed at the insecure endpoint to use the secure HTTPS endpoint with proper client certificates or tokens instead.
5. After removing the flag, verify no other process/firewall rule still exposes an insecure listener (check `netstat`/`ss` on the control-plane node for an unexpected plaintext port).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerInsecureBindAddress.py)
- [Kubernetes API server options reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
