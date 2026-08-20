# CKV_ARGO_2: Ensure Workflow pods are running as non-root user
## Severity
**HIGH** (score: 7.5/10)

Failing to enforce runAsNonRoot lets Workflow pods execute as root, increasing the blast radius of a container compromise (kernel/host attack surface, privilege escalation, container breakout).

## Summary
This check ensures that Argo Workflows templates set `securityContext.runAsNonRoot: true` so that workflow pods cannot run their container processes as root.

## Applicability
**Checkov framework(s):** `argo_workflows`

Applies to Argo Workflows manifests (WorkflowTemplate, Workflow, CronWorkflow, etc.), specifically the `spec` object — checked for a `securityContext` block with `runAsNonRoot` set to `true`.

## Why it matters
Containers that run as root (UID 0) significantly widen the blast radius of any code-execution vulnerability in the workload. If an attacker exploits a vulnerability in the application/image running inside the workflow pod, running as root means they immediately have root-level privileges inside the container — with a much easier path to container breakout, tampering with mounted volumes owned by other UIDs, or exploiting kernel/container-runtime vulnerabilities that specifically require elevated privileges to trigger (e.g. certain namespace or cgroup escapes). Argo Workflow pods frequently mount shared volumes, execute arbitrary user-supplied logic (simulation/batch/postprocessing steps, as reflected in the flagged file names here), and may have Kubernetes API access via their ServiceAccount — combining root execution with those factors substantially increases the impact of a single compromised step. Enforcing `runAsNonRoot: true` causes the kubelet to refuse to start the container at all if the image's default user is root and no non-root UID is specified, forcing this to be caught before deployment rather than in production.

## How Checkov evaluates this
This is a Python check (`BaseArgoWorkflowsCheck`) that operates on the `spec` object. Its `scan_conf` logic:
- **PASSES** only if `spec.securityContext` is present, is a dictionary, and its `runAsNonRoot` key is exactly `True`.
- **FAILS** in all other cases — missing `securityContext`, `securityContext` present but missing `runAsNonRoot`, or `runAsNonRoot` set to `false` (or any non-`True` value).

## Non-compliant example
```yaml
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: batch-workflow-template
spec:
  entrypoint: main
  templates:
    - name: main
      container:
        image: example.com/batch-runner:latest
        command: ["/run.sh"]
  # No securityContext -> pod may run as root
```

## Remediated example
```yaml
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: batch-workflow-template
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  entrypoint: main
  templates:
    - name: main
      container:
        image: example.com/batch-runner:latest
        command: ["/run.sh"]
```

## Remediation steps
1. Add `securityContext.runAsNonRoot: true` to the `spec` of each affected WorkflowTemplate (`batch-workflow-template.yaml`, `postprocess-workflow-template.yaml`, `sim-workflow-template.yaml`).
2. Pair it with an explicit `runAsUser` (a non-zero UID) so the constraint is satisfiable — if the container image's default user is root and no `runAsUser` is set, the pod will fail to start once this is enforced.
3. Verify the application images actually support running as a non-root UID (writable directories, correct file ownership); rebuild images with a dedicated non-root user (`USER` directive) if needed.
4. Consider also setting `readOnlyRootFilesystem: true` and dropping Linux capabilities as further defense-in-depth, since these templates run user-influenced simulation/batch workloads.
5. Re-run Checkov / re-scan to confirm the finding clears in all affected files.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/argo_workflows/checks/template/RunAsNonRoot.py)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
