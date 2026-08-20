# CKV_K8S_41: Ensure that default service accounts are not actively used (ServiceAccount)

## Severity
**LOW** (score: 2.0/10)

Leaving the default ServiceAccount's token auto-mountable means every pod that doesn't specify otherwise silently receives API-server credentials it likely doesn't need, giving a compromised pod an easy lateral-movement credential.

## Summary
This check ensures the automatically-created `default` ServiceAccount in each namespace has `automountServiceAccountToken: false` set, so it cannot be used to authenticate to the Kubernetes API unless explicitly opted back in.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes manifests**: resource kind `ServiceAccount`, only when `metadata.name == "default"`; field `automountServiceAccountToken`.
- **Terraform**: resource types `kubernetes_service_account`, `kubernetes_service_account_v1`, same field, only when the resource's `metadata.name` is `"default"`.

## Why it matters
Every Kubernetes namespace automatically gets a `default` ServiceAccount, and any pod that doesn't explicitly specify a `serviceAccountName` is bound to it. Because it's implicit and easy to forget about, the `default` ServiceAccount tends to accumulate broad or unintentional RBAC bindings over time (someone grants a Role to "default" for a one-off task and never revokes it), and its token is auto-mounted into every pod that uses it — meaning a large, poorly-tracked population of workloads all end up sharing the same identity and, transitively, whatever permissions get bound to it. CIS Benchmark 5.1.5 recommends actively ensuring the default ServiceAccount cannot be used this way: disabling automount on it forces every workload that genuinely needs API access to use an explicitly created, individually scoped ServiceAccount, which makes RBAC auditing and least-privilege enforcement tractable.

## How Checkov evaluates this
The check only applies when the ServiceAccount's `metadata.name` equals `"default"` — any other named ServiceAccount automatically PASSES (out of scope for this rule). For the `default` account, if `automountServiceAccountToken` is explicitly `False`, PASS; otherwise (unset, or any other value) FAIL.

## Non-compliant example
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: payments
# automountServiceAccountToken not set -> defaults to true, token auto-mounted
```

## Remediated example
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: payments
automountServiceAccountToken: false   # added
```

## Remediation steps
1. For every namespace, explicitly manage the `default` ServiceAccount object and set `automountServiceAccountToken: false` on it.
2. For any workload that genuinely needs to call the Kubernetes API, create a dedicated, purpose-named ServiceAccount with only the RBAC permissions it requires, and reference it via `spec.serviceAccountName` in the pod spec — do not re-enable automount on `default`.
3. Audit existing RBAC RoleBindings/ClusterRoleBindings across namespaces for any that reference the `default` ServiceAccount, and migrate them to dedicated accounts (see also CKV_K8S_42, which flags exactly this pattern for RoleBinding/ClusterRoleBinding).
4. Since this can be tedious to apply namespace-by-namespace, consider automating it via a namespace-lifecycle admission webhook or GitOps template that patches `default` on creation.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/DefaultServiceAccount.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/DefaultServiceAccount.py)
- [Kubernetes docs: Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
