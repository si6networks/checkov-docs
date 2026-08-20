# CKV_K8S_119: Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate
## Severity
**HIGH** (score: 7.5/10)

Missing --peer-cert-file/--peer-key-file leaves etcd's inter-node replication traffic unauthenticated and unencrypted, letting an attacker on the cluster network inject into or eavesdrop on the datastore holding all Kubernetes secrets.

## Summary
This check verifies that the `etcd` server has both `--peer-cert-file` and `--peer-key-file` configured, enabling TLS encryption for the peer-to-peer traffic between etcd cluster members.

## Applicability
Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `etcd` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `etcd` component in a multi-member (HA) etcd cluster (CIS Kubernetes Benchmark section 2).

## Why it matters
`--peer-cert-file`/`--peer-key-file` secure the Raft consensus traffic exchanged between etcd cluster members (leader election, log replication, snapshot transfer). This channel carries the same sensitive cluster state (Secrets, etc.) that client-facing traffic does. Without peer TLS, an attacker positioned on the network between etcd nodes could eavesdrop on inter-member replication traffic or, in the worst case, attempt to inject themselves as a rogue peer, compromising cluster consensus integrity. Client-facing TLS (CKV_K8S_116/117) alone does not protect this separate peer channel — both must be secured independently.

## How Checkov evaluates this
The check (`EtcdPeerFiles`) extracts the flag names (`keys`) and values from the container's `command` list using a shared helper (`extract_commands`):
- If `etcd` is not among the extracted keys, the check **PASSES** (not applicable).
- If `etcd` is present, the check requires *both* `--peer-cert-file` and `--peer-key-file` to appear among the extracted keys.
  - If either is missing, the check **FAILS**.
  - If both are present, the check **PASSES**.

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
    - --initial-cluster=etcd-0=http://10.0.0.1:2380,etcd-1=http://10.0.0.2:2380
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
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
    - --initial-cluster=etcd-0=https://10.0.0.1:2380,etcd-1=https://10.0.0.2:2380
```

## Remediation steps
1. Locate the static Pod manifest for `etcd` on each control-plane node (typically `/etc/kubernetes/manifests/etcd.yaml`).
2. Generate a peer TLS certificate/key pair per etcd member, signed by the cluster's (or etcd's dedicated) CA — kubeadm does this automatically for kubeadm-managed clusters.
3. Add `--peer-cert-file=<path>` and `--peer-key-file=<path>` to the `command` array, and update `--initial-cluster`/`--initial-advertise-peer-urls` to use `https://` peer URLs.
4. Also set `--peer-client-cert-auth=true` and `--peer-trusted-ca-file` so peer certificates are actually verified, not just presented (see also CKV_K8S_121).
5. Roll this change out one etcd member at a time on multi-node clusters to avoid losing quorum, and verify cluster health (`etcdctl endpoint health --cluster`) after each member restarts.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/EtcdPeerFiles.py)
- [etcd: Transport security model](https://etcd.io/docs/latest/op-guide/security/)
