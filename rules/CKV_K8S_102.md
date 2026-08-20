# CKV_K8S_102: Ensure that the --etcd-cafile argument is set as appropriate
## Severity
**HIGH** (score: 7.5/10)

Without --etcd-cafile, the API server cannot validate etcd's certificate, exposing the API-server-to-etcd channel, which carries all cluster secrets, to man-in-the-middle interception.

## Summary
This check ensures the Kubernetes API server is started with the `--etcd-cafile` argument set, so it validates etcd's TLS certificate against a trusted CA when connecting to the cluster's data store.

## Applicability
Applies to Kubernetes manifests defining container specs for workload kinds (`CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`) — relevant specifically to the static Pod manifest that runs `kube-apiserver` (typically `/etc/kubernetes/manifests/kube-apiserver.yaml`), since the check looks for the `kube-apiserver` command.

## Why it matters
etcd is the single source of truth for all Kubernetes cluster state, including every Secret, ConfigMap, and RBAC policy in the cluster — anyone able to read or write to etcd directly has effectively complete control of the cluster. The API server is etcd's primary (and typically only sanctioned) client. If `--etcd-cafile` is not configured, the API server has no CA bundle to validate etcd's server certificate against when establishing its TLS connection, meaning it either connects without properly authenticating the etcd endpoint or fails closed depending on the rest of the TLS configuration — either way, the connection lacks the intended cryptographic assurance that it is really etcd on the other end and not an interception point. An attacker positioned on the network path between API server and etcd (e.g., via a compromised node, container escape, or ARP/DNS spoofing on the control-plane network) could potentially intercept or tamper with the entire cluster's state without being detected, since the API server cannot verify it's talking to the legitimate etcd server. This corresponds to CIS Kubernetes Benchmark control 1.2.32.

## How Checkov evaluates this
`ApiServerEtcdCaFile` (a `BaseK8sContainerCheck`) extracts the container's command-line flags via `extract_commands`:
- If the container's command includes `kube-apiserver` (i.e., this is the API server container) and the extracted flag keys do **not** include `--etcd-cafile`, the check **FAILS**.
- In every other case — not the API server container, or `--etcd-cafile` is present — the check **PASSES**.
- Note this only checks for the flag's *presence*, not that its value points to a valid/non-empty CA file path.

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
        - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
        - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
        # missing --etcd-cafile
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
        - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
        - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
        - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt   # fix
```

## Remediation steps
1. Edit the `kube-apiserver` static Pod manifest on each control-plane node to add `--etcd-cafile=<path-to-etcd-ca.crt>`.
2. If using `kubeadm`, this is normally set automatically (`/etc/kubernetes/pki/etcd/ca.crt`) — confirm the flag wasn't stripped by manual edits or custom bootstrap automation.
3. Ensure the referenced CA file actually corresponds to the CA that signed etcd's serving certificate, and that file permissions restrict read access appropriately (it's a CA cert, not a private key, but still keep it under `/etc/kubernetes/pki` with standard ownership).
4. Verify the whole etcd mutual-TLS chain is complete: `--etcd-cafile` (validate etcd's server cert), `--etcd-certfile`/`--etcd-keyfile` (API server's client cert for etcd to validate in return) should all be set together for full mutual authentication.
5. After editing the static manifest, the kubelet restarts the API server automatically — verify cluster health afterward (`kubectl get componentstatuses`, `kubectl get nodes`).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerEtcdCaFile.py)
- [Kubernetes docs: kube-apiserver options (--etcd-cafile)](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
