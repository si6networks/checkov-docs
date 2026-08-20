# CKV_K8S_88: Ensure that the --insecure-port argument is set to 0
## Severity
**CRITICAL** (score: 9.1/10)

A non-zero insecure port serves the Kubernetes API without authentication or authorization, giving unauthenticated network access to cluster administration equivalent to a fully exposed admin interface.

## Summary
This check verifies that a self-managed `kube-apiserver` container explicitly disables its plaintext, unauthenticated HTTP listener by setting `--insecure-port=0`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
The insecure port serves plain HTTP with no TLS and no authentication/authorization checks — any request reaching it is treated as fully privileged (superuser). If this port is not disabled (default was port 8080 in older Kubernetes versions), and it's reachable from anywhere other than strictly localhost, an attacker can read and write arbitrary cluster objects — including Secrets, RBAC bindings, and workload specs — without presenting any credentials. This flag was deprecated starting Kubernetes 1.10 and removed in 1.24, but is still relevant for older or legacy clusters and for auditing IaC templates that target them.

## How Checkov evaluates this
The check (`ApiServerInsecurePort`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is missing or doesn't include `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it FAILS unless the exact literal string `--insecure-port=0` appears in the command list. Any other value (or the flag's total absence) causes a FAILED result — this is one of the few checks in this family that fails when the flag is entirely absent, since `--insecure-port` used to default to a non-zero value in older Kubernetes versions.

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
        - --insecure-port=8080
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
      image: registry.k8s.io/kube-apiserver:v1.18.0
      command:
        - kube-apiserver
        - --insecure-port=0
        - --etcd-servers=https://127.0.0.1:2379
```

## Remediation steps
1. Set `--insecure-port=0` explicitly in the `kube-apiserver` command/args on the static pod manifest (typically `/etc/kubernetes/manifests/kube-apiserver.yaml`).
2. If running Kubernetes 1.24+, the `--insecure-port` flag has been removed from the binary entirely and the insecure listener no longer exists — you can safely omit the flag rather than set it to 0 (specifying it will error on newer kubeadm/kube-apiserver builds).
3. Ensure all clients (kubectl, controllers, operators) are configured to use the secure HTTPS port (`--secure-port`, default 6443) with valid certificates/tokens before disabling the insecure port, to avoid breaking existing integrations that may still target the plaintext endpoint.
4. After the change, verify the insecure port is closed: `curl http://<apiserver-ip>:8080/healthz` should fail/connection-refuse.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerInsecurePort.py)
- [Kubernetes API server options reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
