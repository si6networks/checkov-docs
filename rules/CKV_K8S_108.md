# CKV_K8S_108: Ensure that the --use-service-account-credentials argument is set to true
## Severity
**HIGH** (score: 7.5/10)

Without --use-service-account-credentials, all built-in controllers share the root credential instead of distinct, least-privilege service account tokens, increasing the blast radius if the controller-manager's credential is ever leaked or misused.

## Summary
This check verifies that `kube-controller-manager` is started with `--use-service-account-credentials=true`, so that each individual controller loop authenticates to the API server using its own distinct service account rather than the controller manager's single shared credential.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `kube-controller-manager` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice it only meaningfully evaluates the static Pod manifest for the `kube-controller-manager` control-plane component.

## Why it matters
By default, without this flag, all controller loops inside `kube-controller-manager` (deployment controller, replicaset controller, node controller, etc.) share one identity and set of RBAC permissions — effectively the union of everything any controller needs. This violates least-privilege: a bug or compromise affecting one controller loop has access to the permissions of all of them. Setting `--use-service-account-credentials=true` makes each controller authenticate as its own dedicated `system:serviceaccount:kube-system:<controller-name>` identity, each bound to only the RBAC permissions that specific controller needs, following the CIS Kubernetes Benchmark recommendation and reducing blast radius if a controller is compromised.

## How Checkov evaluates this
The check (`KubeControllerManagerServiceAccountCredentials`) inspects the container's `command` list:
- If `command` is absent, or does not include `kube-controller-manager`, the check **PASSES** (not applicable).
- If `kube-controller-manager` is present, it scans tokens for one starting with `--use-service-account-credentials`; the value after `=` is compared to the string `"true"`.
  - As soon as `--use-service-account-credentials=true` is found, it **PASSES**.
  - If the loop completes without finding that exact flag/value, it **FAILS** (flag missing or set to `false`).

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
spec:
  containers:
  - name: kube-controller-manager
    image: k8s.gcr.io/kube-controller-manager:v1.28.0
    command:
    - kube-controller-manager
    - --profiling=false
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
spec:
  containers:
  - name: kube-controller-manager
    image: k8s.gcr.io/kube-controller-manager:v1.28.0
    command:
    - kube-controller-manager
    - --profiling=false
    - --use-service-account-credentials=true
```

## Remediation steps
1. Locate the static Pod manifest for `kube-controller-manager` (typically `/etc/kubernetes/manifests/kube-controller-manager.yaml`).
2. Add `--use-service-account-credentials=true` to the container `command` array.
3. Ensure the corresponding controller service accounts (auto-created in `kube-system` by kubeadm) have appropriate RBAC bindings — most standard distributions already provision these correctly.
4. Save the manifest; the static Pod restarts automatically to pick up the change.
5. This flag has no effect on fully managed control planes where you don't operate `kube-controller-manager` directly (EKS/GKE/AKS); exclude such manifests from this check if it isn't actionable in your environment.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerServiceAccountCredentials.py)
- [Kubernetes kube-controller-manager reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
