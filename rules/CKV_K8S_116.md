# CKV_K8S_116: Ensure that the --cert-file and --key-file arguments are set as appropriate
## Severity
**HIGH** (score: 7.5/10)

Etcd is the datastore backing every Kubernetes Secret and cluster object, and without --cert-file/--key-file its client traffic is unencrypted and unauthenticated, letting anyone with network access read or tamper with all cluster secrets and state.

## Summary
This check verifies that the `etcd` server is configured with both `--cert-file` and `--key-file` arguments, enabling TLS encryption for client-to-server communication with etcd.

## Applicability
Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `etcd` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `etcd` component (typically `/etc/kubernetes/manifests/etcd.yaml` on kubeadm clusters, per CIS Kubernetes Benchmark 2.1).

## Why it matters
etcd is the single source of truth for all Kubernetes cluster state — every Secret, ConfigMap, RBAC binding, and object definition lives there. Without `--cert-file`/`--key-file` configured, etcd's client API listens over plaintext HTTP rather than HTTPS, meaning any traffic between the API server and etcd (including Secret data in transit) can be intercepted or tampered with by anyone with network access to that link. This is one of the most consequential CIS Kubernetes Benchmark findings (2.1) because a compromised etcd channel effectively means a compromised cluster — an attacker who can read etcd traffic can extract every Secret and, if they can write, can inject arbitrary cluster state.

## How Checkov evaluates this
The check (`EtcdCertAndKey`) inspects the container's `command` list:
- If `command` is absent, or does not include `etcd`, the check **PASSES** (not applicable).
- If `etcd` is present, it scans tokens in order, setting `hasCertCommand = True` when a token starts with `--cert-file`, and `hasKeyCommand = True` when a token starts with `--key-file`.
  - As soon as both flags have been seen, it **PASSES**.
  - If the loop completes without both being set, it **FAILS**.

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
    - --data-dir=/var/lib/etcd
    - --listen-client-urls=http://127.0.0.1:2379
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
    - --data-dir=/var/lib/etcd
    - --listen-client-urls=https://127.0.0.1:2379
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --key-file=/etc/kubernetes/pki/etcd/server.key
```

## Remediation steps
1. Locate the static Pod manifest for `etcd` (typically `/etc/kubernetes/manifests/etcd.yaml`).
2. Generate (or use the kubeadm-provisioned) TLS server certificate/key pair for etcd, signed by the cluster (or a dedicated etcd) CA.
3. Add `--cert-file=<path-to-cert>` and `--key-file=<path-to-key>` to the `command` array, and update `--listen-client-urls` to use `https://` instead of `http://`.
4. Update the API server's etcd client configuration (`--etcd-certfile`, `--etcd-keyfile`, `--etcd-cafile`) to present a client certificate trusted by etcd, since enabling server TLS alone doesn't complete mutual trust.
5. Restart the static Pod (automatic on manifest change) and verify `kubectl get --raw /healthz/etcd` or `etcdctl` connectivity still works over TLS before decommissioning any prior plaintext access path.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/EtcdCertAndKey.py)
- [etcd: Transport security model](https://etcd.io/docs/latest/op-guide/security/)
