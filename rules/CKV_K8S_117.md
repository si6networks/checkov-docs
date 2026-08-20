# CKV_K8S_117: Ensure that the --client-cert-auth argument is set to true
## Severity
**MEDIUM** (score: 5.0/10)

Without --client-cert-auth=true, etcd accepts client connections without verifying a client certificate, allowing any network-reachable client to read and write the full contents of the cluster's secret store and object state.

## Summary
This check verifies that the `etcd` server requires client certificate authentication (`--client-cert-auth=true`) for its client API, rather than accepting unauthenticated connections.

## Applicability
Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `etcd` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `etcd` component (CIS Kubernetes Benchmark 2.2).

## Why it matters
Even with TLS enabled on etcd's client endpoint, TLS alone only encrypts the channel — it doesn't by itself restrict *who* can connect. `--client-cert-auth=true` forces every client (chiefly the kube-apiserver) to present a valid client certificate signed by a trusted CA before etcd will serve requests. Without it, anyone who can reach the etcd client port over the network — even without valid credentials — could potentially read or write raw cluster state, including every Secret in the cluster, completely bypassing Kubernetes' RBAC and admission control layers. This is a critical CIS Kubernetes Benchmark (2.2) hardening item precisely because etcd sits underneath, not behind, the API server's authorization model.

## How Checkov evaluates this
The check (`EtcdClientCertAuth`) inspects the container's `command` list:
- If `command` is not a list, the check **PASSES** (not evaluable).
- If `etcd` is in the command list, it checks whether the exact literal string `--client-cert-auth=true` is present anywhere in `command`.
  - If present, the check **PASSES**.
  - If absent (flag missing, or set to `false`, or written with different spacing), the check **FAILS**.

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
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --key-file=/etc/kubernetes/pki/etcd/server.key
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
    - --client-cert-auth=true
```

## Remediation steps
1. Locate the static Pod manifest for `etcd` (typically `/etc/kubernetes/manifests/etcd.yaml`).
2. Add `--client-cert-auth=true` to the `command` array as its own literal entry.
3. Ensure a trusted CA certificate is configured (`--trusted-ca-file`) so etcd can validate incoming client certificates against the correct authority.
4. Confirm the API server is already configured with `--etcd-certfile`/`--etcd-keyfile` pointing at a valid client certificate signed by that CA — otherwise enabling this flag will break API server-to-etcd connectivity.
5. Save the manifest, let the static Pod restart, and verify `kubectl get nodes` (or any API call that hits etcd) still succeeds before considering the change complete.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/EtcdClientCertAuth.py)
- [etcd: Transport security model](https://etcd.io/docs/latest/op-guide/security/)
