# CKV_K8S_144: Ensure that the --protect-kernel-defaults argument is set to true
## Severity
**LOW** (score: 2.0/10)

Disabling --protect-kernel-defaults allows kubelet to silently modify kernel sysctl parameters, weakening the node's defense-in-depth against kernel-level tuning drift rather than granting direct exploit access.

## Summary
This check ensures the kubelet is started with `--protect-kernel-defaults=true`, causing it to fail-fast if host kernel parameters don't match the values the kubelet expects rather than silently overriding them.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting when it invokes `kubelet`.

## Why it matters
Certain kubelet-managed kernel parameters (e.g., for OOM behavior, memory limits) can drift from expected node baselines because of manual tuning, other software, or misconfiguration. With `--protect-kernel-defaults=false` (the default in many distros), the kubelet will silently modify kernel settings to match its expectations if they differ — this can mask underlying host misconfiguration and creates unpredictable node behavior since kernel settings intended by the node's administrators are overwritten without visibility. Worse, a compromised or misbehaving kubelet, or a misconfigured node, could have kernel parameters silently "corrected" in ways that weaken host hardening. Setting `--protect-kernel-defaults=true` makes the kubelet fail to start instead of silently modifying kernel settings, surfacing configuration drift explicitly so it can be reviewed and fixed deliberately. This is CIS Kubernetes Benchmark control 4.2.6.

## How Checkov evaluates this
The check (`KubeletProtectKernelDefaults`) looks at each container's `command` list:
1. If `kubelet` is among the command tokens, it checks whether `--protect-kernel-defaults=true` is present as an exact string in the command list.
2. If that exact flag/value is **not** present, the check **FAILS** — this includes the flag being entirely absent, set to `false`, or expressed with different casing/spacing.
3. If present, the check **PASSES**.

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
        - --authorization-mode=Webhook
        # --protect-kernel-defaults missing (defaults to false)
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
        - --authorization-mode=Webhook
        - --protect-kernel-defaults=true
```

## Remediation steps
1. Add `--protect-kernel-defaults=true` to the kubelet command line (or `protectKernelDefaults: true` in the `KubeletConfiguration` file).
2. Before rolling out broadly, audit actual node kernel settings against kubelet's expected defaults (e.g., via a test/staging node) — with this flag enabled, mismatches will prevent the kubelet from starting, so pre-emptively align kernel sysctls (e.g., `vm.overcommit_memory`, `vm.panic_on_oom`, `kernel.panic`, `kernel.panic_on_oops`) to the values the kubelet expects.
3. Roll out node-by-node and monitor kubelet startup logs closely; a failed kubelet means the node goes `NotReady`, so this is a change to make carefully, ideally node group by node group.
4. Document the required kernel sysctl baseline for new nodes/AMIs so future nodes are provisioned compliant from the start.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletProtectKernelDefaults.py
