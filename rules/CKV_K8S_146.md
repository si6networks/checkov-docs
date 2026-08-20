# CKV_K8S_146: Ensure that the --hostname-override argument is not set
## Severity
**LOW** (score: 2.0/10)

Setting --hostname-override can bypass TLS bootstrap hostname verification for the kubelet, weakening node identity assurance and making certificate/hostname spoofing between nodes and the control plane easier.

## Summary
This check ensures the kubelet's `--hostname-override` argument is not set, so the kubelet uses the node's true hostname/identity for all cluster operations.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting when it invokes `kubelet`.

## Why it matters
`--hostname-override` lets the kubelet register the node under an arbitrary name instead of its actual hostname. This is discouraged because it can be used to circumvent hostname-based access restrictions and audit trails — cloud-provider integrations, certificate validation, and node-identity-based security controls (e.g., TLS bootstrapping and the Node authorizer, which authorizes kubelets to only access objects related to their own node based on identity) can be undermined if a node can present itself under a name that doesn't match its actual/expected identity. It also risks confusion in logging, monitoring, and node-to-node trust relationships, and can be leveraged by an attacker with control of kubelet startup parameters to make a compromised or rogue node masquerade as a different, possibly more-trusted node. CIS Kubernetes Benchmark control 4.2.8 recommends leaving this unset so identity is derived from the actual system hostname.

## How Checkov evaluates this
The check (`KubeletHostnameOverride`) looks at each container's `command` list:
1. If `kubelet` is among the command tokens, it splits every command-line argument on `=` and takes the key portion.
2. If `--hostname-override` appears as one of those keys (regardless of what value it's set to), the check **FAILS**.
3. If the flag is absent entirely, the check **PASSES**.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-static-pod
spec:
  containers:
    - name: kubelet
      image: k8s.gcr.io/hyperkube:v1.20.0
      command:
        - kubelet
        - --hostname-override=node-alias-01
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-static-pod
spec:
  containers:
    - name: kubelet
      image: k8s.gcr.io/hyperkube:v1.20.0
      command:
        - kubelet
        # --hostname-override removed entirely
```

## Remediation steps
1. Remove `--hostname-override` from the kubelet command line entirely.
2. If node naming needs to differ from the raw hostname for legitimate operational reasons (e.g., cloud provider naming schemes), address this via proper node naming/cloud-provider integration mechanisms rather than `--hostname-override`, and evaluate whether the underlying need can be met through DNS/hostname configuration at the OS level instead.
3. Roll out node-by-node; note that changing a node's registered name (by removing an override) will effectively make it appear as a "new" node to the cluster, so plan for cordon/drain and rejoin rather than an in-place change on already-running nodes.
4. Re-verify node labels/taints and any external inventory system tied to the previous overridden name after the change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletHostnameOverride.py
