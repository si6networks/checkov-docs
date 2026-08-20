# CKV_ARGO_1: Ensure Workflow pods are not using the default ServiceAccount
## Severity
**MEDIUM** (score: 5.5/10)

Running Workflow pods under the default ServiceAccount risks granting workflow tasks broader in-cluster API permissions than needed, enabling lateral movement or privilege escalation if a task is compromised, though impact depends on what is bound to the default SA.

## Summary
This check ensures that Argo Workflows templates explicitly assign a non-default Kubernetes ServiceAccount to workflow pods rather than falling back to the namespace's `default` ServiceAccount.

## Applicability
Applies to Argo Workflows manifests (WorkflowTemplate, Workflow, CronWorkflow, etc.), specifically the `spec` object of a workflow/template — checked for presence and value of `serviceAccountName`.

## Why it matters
Every namespace's `default` ServiceAccount is automatically mounted into pods that don't specify one, and its associated token can be used to authenticate to the Kubernetes API server. In many clusters the `default` ServiceAccount ends up with broader (or simply undifferentiated) RBAC bindings than intended, and because it's shared by every pod in the namespace that doesn't request a specific identity, a compromised workflow pod running under `default` inherits whatever permissions any other workload has accumulated on that ServiceAccount over time. This violates least-privilege and makes it hard to reason about (or audit) which workloads can do what against the API server. Argo Workflows in particular often run with elevated permissions to orchestrate other Kubernetes resources (creating pods, reading secrets, managing other workflow steps), so an attacker who compromises a workflow pod using the `default` ServiceAccount may be able to pivot to broader cluster access, including reading other namespace secrets or manipulating unrelated workloads.

## How Checkov evaluates this
This is a Python check (`BaseArgoWorkflowsCheck`) that operates on the `spec` object. Its `scan_conf` logic:
- **PASSES** if the `spec` contains a `serviceAccountName` key AND its value is not the literal string `"default"`.
- **FAILS** in all other cases — i.e., if `serviceAccountName` is missing entirely, or if it is present but explicitly set to `"default"`.

## Non-compliant example
```yaml
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: sim-workflow-template
spec:
  entrypoint: main
  templates:
    - name: main
      container:
        image: example.com/sim-runner:latest
        command: ["/run.sh"]
  # No serviceAccountName specified -> falls back to the namespace's "default" SA
```

## Remediated example
```yaml
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: sim-workflow-template
spec:
  serviceAccountName: sim-workflow-runner   # dedicated, scoped ServiceAccount
  entrypoint: main
  templates:
    - name: main
      container:
        image: example.com/sim-runner:latest
        command: ["/run.sh"]
```

## Remediation steps
1. Create a dedicated Kubernetes ServiceAccount for each workflow/template (e.g. `sim-workflow-runner`) with a minimal RBAC Role/RoleBinding scoped to exactly what the workflow needs.
2. Set `spec.serviceAccountName` on the Workflow/WorkflowTemplate to that dedicated ServiceAccount — never `default`.
3. Also disable auto-mounting of the default token where not needed (`automountServiceAccountToken: false` on the default ServiceAccount) as defense-in-depth.
4. Apply this to every overlay/environment (dev, staging, prod) — the flagged files are overlay patches, so check the corresponding base templates too.
5. Re-run Checkov / re-scan to confirm the finding clears in all affected files.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/argo_workflows/checks/template/DefaultServiceAccount.py)
- [Kubernetes: Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
