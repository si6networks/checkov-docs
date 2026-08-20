# CKV_K8S_106: Ensure that the --terminated-pod-gc-threshold argument is set as appropriate
## Severity
**MEDIUM** (score: 5.0/10)

Missing a terminated-pod-gc-threshold mainly risks unbounded growth of terminated pod objects on the control plane, an availability/hygiene concern rather than a direct path to compromise or data exposure.

## Summary
This check verifies that the `kube-controller-manager` is configured with a `--terminated-pod-gc-threshold` value greater than zero, so that terminated Pod objects are periodically garbage-collected rather than accumulating indefinitely.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests (raw YAML/JSON, and any Helm/Kustomize output Checkov renders to Kubernetes objects) that define a Pod-carrying workload whose container command line invokes `kube-controller-manager`. Applicable entity kinds: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice this check only fires meaningfully on the static Pod manifest used to run the control-plane `kube-controller-manager` component (e.g. `/etc/kubernetes/manifests/kube-controller-manager.yaml` on a kubeadm cluster), since it inspects the container's `command` array for that binary name.

## Why it matters
Terminated Pods (Succeeded/Failed) that are never garbage-collected accumulate in etcd. Over time this bloats the etcd data store, slows down API server list/watch operations against the Pod resource, and can contribute to control-plane memory and I/O pressure — a availability/reliability risk on busy clusters that run many short-lived Jobs or CronJobs. Setting `--terminated-pod-gc-threshold` to a sane positive value bounds how many terminated Pods are retained before the controller manager cleans them up, keeping the object store size predictable. This maps to CIS Kubernetes Benchmark guidance on controller-manager arguments.

## How Checkov evaluates this
The check (`KubeControllerManagerTerminatedPods`, a `BaseK8sContainerCheck`) inspects the container's `command` list:
- If `command` is absent, or the command list does not include `kube-controller-manager`, the check **PASSES** (not applicable — it only evaluates the controller-manager container).
- If `kube-controller-manager` is present, it scans each token in `command`:
  - If it finds the token exactly equal to `--terminated-pod-gc-threshold` (no `=`, i.e. flag with a separate value argument), it **PASSES** immediately.
  - If it finds a token starting with `--terminated-pod-gc-threshold` (i.e. `--terminated-pod-gc-threshold=N` form), it parses the value after `=` and casts to `int`; if `> 0` it **PASSES**, otherwise **FAILS**.
  - If the loop completes without finding the flag at all, it **FAILS**.

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
    - --terminated-pod-gc-threshold=0
    - --use-service-account-credentials=true
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
    - --terminated-pod-gc-threshold=12500
    - --use-service-account-credentials=true
```

## Remediation steps
1. Locate the static Pod manifest for `kube-controller-manager` (typically `/etc/kubernetes/manifests/kube-controller-manager.yaml` on kubeadm-managed control planes, or the equivalent Helm chart values for managed distributions that expose it).
2. Add `--terminated-pod-gc-threshold=<N>` to the container's `command` array, where `N` is a positive integer (the upstream Kubernetes default is `12500`).
3. If your cluster is a managed offering (EKS, GKE, AKS) you typically do not control this flag directly — this check mainly applies to self-managed/on-prem control planes; consider excluding it via Checkov's skip mechanism for managed clusters where it does not apply.
4. Save the manifest; kubelet will pick up static Pod changes and restart the component automatically — no `kubectl apply` needed for static Pods.
5. Re-run Checkov to confirm the check passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeControllerManagerTerminatedPods.py)
- [Kubernetes kube-controller-manager reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
