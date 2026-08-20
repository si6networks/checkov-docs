# CKV_K8S_118: Ensure that the --auto-tls argument is not set to true
## Severity
**HIGH** (score: 7.5/10)

Enabling --auto-tls causes etcd to generate self-signed certificates automatically instead of using a properly managed CA, undermining the trust chain and making the peer/client TLS vulnerable to impersonation and man-in-the-middle attacks.

## Summary
This check verifies that the `etcd` server does not enable `--auto-tls=true`, which would make etcd generate and use self-signed client-facing TLS certificates automatically instead of using certificates issued by the cluster's trusted CA.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `etcd` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `etcd` component (CIS Kubernetes Benchmark 2.3).

## Why it matters
`--auto-tls=true` has etcd generate its own self-signed certificate at startup rather than using a certificate chain rooted in a CA that clients (and administrators) explicitly trust and manage. Self-signed, auto-generated certificates undermine the point of certificate-based trust: there is no independent authority vouching for the server's identity, no consistent certificate lifecycle/rotation policy, and no straightforward way to revoke or audit trust. Combined with client cert auth requirements elsewhere, relying on auto-generated certs makes it harder to enforce a coherent PKI across the cluster and can mask misconfiguration (e.g. silently "working" with TLS while using throwaway certs instead of the intended, properly managed ones) — a CIS Kubernetes Benchmark (2.3) finding.

## How Checkov evaluates this
The check (`EtcdAutoTls`) inspects the container's `command` list:
- If `command` is not a list, the check **PASSES** (not evaluable).
- If `etcd` is in the command list and the exact literal string `--auto-tls=true` is also present in `command`, the check **FAILS**.
- In every other case (flag absent, or explicitly `--auto-tls=false`), the check **PASSES**.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: etcd
  namespace: kube-system
spec:
  containers:
  - name: etcd
    image: registry.k8s.io/etcd:3.5.9-0
    command:
    - etcd
    - --auto-tls=true
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: etcd
  namespace: kube-system
spec:
  containers:
  - name: etcd
    image: registry.k8s.io/etcd:3.5.9-0
    command:
    - etcd
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --key-file=/etc/kubernetes/pki/etcd/server.key
    - --auto-tls=false
```

## Remediation steps
1. Locate the static Pod manifest for `etcd` (typically `/etc/kubernetes/manifests/etcd.yaml`).
2. Remove `--auto-tls=true` (or set it explicitly to `false`) from the `command` array.
3. Provision proper `--cert-file`/`--key-file` (and, for peer traffic, `--peer-cert-file`/`--peer-key-file`) using certificates signed by the cluster's trusted CA (see CKV_K8S_116 and CKV_K8S_119).
4. Ensure `--client-cert-auth=true` is also set (CKV_K8S_117) so the properly-issued certificates are actually being enforced, not just present.
5. Save the manifest, let the static Pod restart, and verify etcd connectivity/health (`etcdctl endpoint health`) using the new certificate chain before removing any temporary auto-TLS fallback.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/EtcdAutoTls.py)
- [etcd: Transport security model](https://etcd.io/docs/latest/op-guide/security/)
