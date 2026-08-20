# CKV_K8S_99: Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate
## Severity
**HIGH** (score: 7.5/10)

Without TLS client certificates configured for etcd, the API server's connection to the cluster's primary data store (holding all secrets and cluster state) is unauthenticated and/or unencrypted, exposing all cluster secrets to interception or unauthorized access.

## Summary
This check verifies that a self-managed `kube-apiserver` container configures both `--etcd-certfile` and `--etcd-keyfile`, enabling mutual TLS (mTLS) client authentication to the etcd datastore.

## Applicability
Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
etcd is the single source of truth for all Kubernetes cluster state — every Secret, ConfigMap, RBAC binding, and workload spec lives there. The connection between `kube-apiserver` and etcd must be mutually authenticated: without client certificates (`--etcd-certfile`/`--etcd-keyfile`), etcd cannot cryptographically verify that the connecting client is actually the legitimate API server, and depending on etcd's own configuration, this can allow any network-reachable client presenting only server-side TLS (or none) to interact with etcd directly, completely bypassing Kubernetes RBAC, admission control, and audit logging — since those all live in the API server layer, not in etcd itself. A compromised or spoofed connection to etcd is effectively full, unaudited read/write access to the entire cluster's state, including all Secrets in plaintext (etcd does not encrypt data by default unless `--encryption-provider-config` is separately configured).

## How Checkov evaluates this
The check (`ApiServerEtcdCertAndKey`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
1. If `command` is `None` or doesn't contain `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it scans every argument and sets a flag `hasCertCommand = True` if any argument starts with `--etcd-certfile`, and `hasKeyCommand = True` if any starts with `--etcd-keyfile`.
3. Returns PASSED only if **both** flags were found; FAILED if either (or both) is missing. It does not validate the actual file paths or extensions, only that both flag prefixes are present.

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
        - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
        # missing --etcd-certfile and --etcd-keyfile: no client mTLS
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
        - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
        - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
        - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
```

## Remediation steps
1. Generate (or, for kubeadm clusters, locate the already-generated) client certificate/key pair for the API server to authenticate to etcd — kubeadm places these at `/etc/kubernetes/pki/apiserver-etcd-client.crt` and `.key` by default.
2. Add `--etcd-certfile=<path-to-cert>` and `--etcd-keyfile=<path-to-key>` to the `kube-apiserver` command, alongside the existing `--etcd-cafile` and `--etcd-servers`.
3. Ensure etcd itself is configured to require and verify client certificates (`--client-cert-auth=true` and matching `--trusted-ca-file` on the etcd side) — setting the flags on the API server alone doesn't enforce mTLS if etcd will accept unauthenticated connections.
4. Mount the certificate and key files into the static pod via `hostPath` volumes if not already present.
5. Verify connectivity after the change: check `kube-apiserver` logs for etcd connection errors and confirm `kubectl get pods --all-namespaces` still returns data (a broken etcd connection will make the entire API server non-functional).
6. Rotate these certificates periodically per your PKI policy, and ensure your certificate-renewal automation (e.g., `kubeadm certs renew`) covers this specific cert.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerEtcdCertAndKey.py)
- [Kubernetes etcd security documentation](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
