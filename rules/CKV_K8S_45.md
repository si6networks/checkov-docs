# CKV_K8S_45: Ensure the Tiller Deployment (Helm V2) is not accessible from within the cluster

## Severity
**HIGH** (score: 8.0/10)

If Tiller's gRPC listener is reachable from other pods rather than bound to localhost, any workload on the cluster network can talk to it and inherit its cluster-admin-equivalent privileges without authentication, a well-known Helm v2 attack path.

## Summary
For any container identified as Tiller (Helm v2's server component), this check ensures its gRPC listener is bound only to `localhost`/`127.0.0.1` rather than being reachable from the rest of the cluster network.

## Applicability
Kubernetes manifests only, container-level check across kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. This check only evaluates containers that are already identified as Tiller by the shared `Tiller.is_tiller()` helper (same image/label heuristic used by CKV_K8S_34); for any non-Tiller container it returns `UNKNOWN` (not applicable).

## Why it matters
Tiller's gRPC API had no built-in authentication — access control depended entirely on network reachability. If Tiller's listener is bound to all interfaces (the historical default) and reachable from the pod network, any compromised pod anywhere in the cluster (or, depending on NetworkPolicy configuration, any pod at all) can connect to it and instruct it to install, modify, or delete Helm releases, typically leveraging Tiller's own broad RBAC grant to escalate privileges far beyond the compromised pod's own permissions. Binding Tiller's `--listen` flag to `localhost`/`127.0.0.1` restricts it to same-pod/same-network-namespace access only, meaning an attacker would need to already be running code inside the Tiller pod itself (rather than anywhere else in the cluster) to reach it — a much narrower and less likely position for an external attacker to reach. This check is a compensating control specifically for environments that still have Tiller running (ideally decommissioned instead — see CKV_K8S_34/44), reducing its exposure if outright removal isn't yet possible.

## How Checkov evaluates this
For containers that match the Tiller heuristic (image contains `tiller`, or labels `app == helm` / `name == tiller`), the check inspects the container's `args`: if any argument contains `--listen` together with `localhost` or `127.0.0.1` (e.g. `--listen=localhost:44134`), the check PASSES. If Tiller is detected but no such restricted `--listen` argument is found, it FAILS. Non-Tiller containers are not evaluated (`UNKNOWN`).

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tiller-deploy
  labels:
    app: helm
    name: tiller
spec:
  template:
    metadata:
      labels:
        app: helm
        name: tiller
    spec:
      containers:
        - name: tiller
          image: gcr.io/kubernetes-helm/tiller:v2.17.0
          # no --listen restriction -> reachable from the whole pod network
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tiller-deploy
  labels:
    app: helm
    name: tiller
spec:
  template:
    metadata:
      labels:
        app: helm
        name: tiller
    spec:
      containers:
        - name: tiller
          image: gcr.io/kubernetes-helm/tiller:v2.17.0
          args:
            - --listen=localhost:44134   # restrict Tiller to local access only
```

## Remediation steps
1. Preferred: remove Tiller entirely and migrate to Helm v3 (see CKV_K8S_34/CKV_K8S_44) — this check is only a mitigation for environments that cannot yet decommission Tiller.
2. If Tiller must remain temporarily, add `--listen=localhost:44134` to its container `args` so the gRPC port is only reachable via `kubectl port-forward`/`localhost`, not from other pods in the cluster.
3. Additionally apply a `NetworkPolicy` restricting ingress to the Tiller pod to only the specific administrative source that legitimately needs it, as defense in depth beyond the listen-address restriction.
4. Track and prioritize full Tiller removal, since even a localhost-restricted Tiller is running end-of-life, unpatched software.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/TillerDeploymentListener.py)
- [Helm docs: Migrate from Helm v2 to v3](https://helm.sh/docs/topics/v2_v3_migration/)
