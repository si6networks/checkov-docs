# CKV_K8S_121: Ensure that the --peer-client-cert-auth argument is set to true
## Severity
**HIGH** (score: 7.5/10)

Without --peer-client-cert-auth=true on the etcd container, peer-to-peer replication connections are not authenticated, allowing an attacker with network access to impersonate a cluster member and read or corrupt the secrets/state stored in etcd.

## Summary
This check verifies that a Pod named `etcd` requires client certificate authentication on its peer (member-to-member) endpoint, by requiring `--peer-client-cert-auth=true` in the container's `args`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only, restricted specifically to entity kind `Pod` — and further specifically to a Pod whose `metadata.name` is exactly `etcd` (the standard static Pod name for the etcd component on kubeadm-managed clusters). Other Pods are not evaluated by this check.

## Why it matters
`--peer-cert-file`/`--peer-key-file` (CKV_K8S_119) encrypt etcd's inter-member Raft traffic, but encryption alone doesn't verify *who* is on the other end of the connection. `--peer-client-cert-auth=true` requires every peer connection to present a client certificate signed by a trusted CA before it is accepted into the cluster's consensus protocol. Without this, an attacker who can reach the peer port over the network could attempt to inject a rogue member into the etcd cluster or otherwise interfere with Raft consensus, since TLS alone (without client cert enforcement) only prevents passive eavesdropping, not active impersonation of a legitimate peer.

## How Checkov evaluates this
The check (`PeerClientCertAuthTrue`, a `BaseK8Check` scanning Pod specs) only evaluates a Pod when `metadata.name == "etcd"`; for any other Pod name it returns `UNKNOWN` (not applicable/not evaluated).
For the matching `etcd` Pod:
- It iterates `spec.containers`.
- For each container, if `args` is present (not `None`), it checks whether the exact literal string `--peer-client-cert-auth=true` is present in that container's `args` list.
  - If any container has `args` set but is missing `--peer-client-cert-auth=true`, the check **FAILS** immediately.
- If the loop over all containers completes without failing, the check **PASSES**.
- Note this check specifically inspects the `args` field (not `command`, unlike the other etcd/controller-manager checks in this family).

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
    args:
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
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
    args:
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
    - --peer-client-cert-auth=true
```

## Remediation steps
1. Locate the static Pod manifest for `etcd` (typically `/etc/kubernetes/manifests/etcd.yaml`) and confirm its Pod name is `etcd` (this check ignores etcd Pods under any other name).
2. Add `--peer-client-cert-auth=true` to the container's `args` (kubeadm-generated manifests commonly use `command` for the etcd binary invocation and separately populate `args`/flags in the same list — confirm which field your manifest uses, since this specific Checkov check only inspects `args`).
3. Ensure `--peer-trusted-ca-file` is set so peer client certificates are validated against the correct CA.
4. Confirm every other etcd member's certificate is signed by that trusted CA before enabling enforcement cluster-wide, to avoid a member being locked out of the Raft group.
5. Roll the change out one etcd member at a time in an HA cluster, checking `etcdctl endpoint health --cluster` after each restart.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/PeerClientCertAuthTrue.py)
- [etcd: Transport security model](https://etcd.io/docs/latest/op-guide/security/)
