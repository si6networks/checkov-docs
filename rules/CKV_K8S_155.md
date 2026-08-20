# CKV_K8S_155: Minimize ClusterRoles that grant control over validating or mutating admission webhook configurations
## Severity
**HIGH** (score: 7.5/10)

A ClusterRole able to create/update/patch admission webhook configurations can install or alter mutating/validating webhooks to intercept or bypass admission control cluster-wide, effectively enabling privilege escalation.

## Summary
This check flags any `ClusterRole` that grants `create`, `update`, or `patch` permissions on `mutatingwebhookconfigurations` or `validatingwebhookconfigurations` in the `admissionregistration.k8s.io` API group.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests of `kind: ClusterRole`. Inspects the role's `rules` for any rule combining `apiGroups: [admissionregistration.k8s.io]`, verbs including `create`/`update`/`patch`, and resources including `mutatingwebhookconfigurations` or `validatingwebhookconfigurations`.

## Why it matters
`MutatingWebhookConfiguration` and `ValidatingWebhookConfiguration` objects tell the API server to call out to an external webhook service for every matching API request, before or as part of admission. Anyone who can create or modify these objects can register a webhook that intercepts arbitrary API requests cluster-wide (subject to the webhook's configured scope) — a mutating webhook can silently alter any resource it intercepts (e.g., inject a sidecar container with attacker-controlled image and host mounts into every new Pod in the cluster, or change environment variables/secrets references), and even a validating webhook can be used to deny legitimate operations (denial of service) or, if the webhook endpoint itself is attacker-controlled, receive a copy of sensitive request payloads (potentially containing Secrets or other confidential data) as they pass through admission. Because webhook configurations apply cluster-wide and execute with high implicit trust from the API server, a `ClusterRole` granting write access to them is effectively a path to broad cluster compromise or persistence (an attacker could install a mutating webhook that injects a backdoor into every future pod). This maps to a hardening recommendation similar in spirit to CIS Kubernetes Benchmark RBAC minimization guidance: cluster-admin-adjacent permissions like this should be tightly scoped to only the specific controllers that legitimately need them (e.g., `cert-manager-cainjector`, which registers webhook configurations to keep CA bundles injected — a case that commonly triggers this finding legitimately, but should still be reviewed to ensure the RoleBinding scope is as narrow as possible).

## How Checkov evaluates this
The check (`RbacControlWebhooks`, extending `BaseRbacK8sCheck`) applies to `ClusterRole` resources and defines one "failing operation" pattern:
- `apiGroups: ["admissionregistration.k8s.io"]`
- `verbs: ["create", "update", "patch"]`
- `resources: ["mutatingwebhookconfigurations", "validatingwebhookconfigurations"]`

The base RBAC check logic examines each rule in the ClusterRole's `rules` list; if any rule's `apiGroups`, `verbs`, and `resources` overlap with (grant any of) this failing combination, the check **FAILS**. A `ClusterRole` whose rules don't touch this API group/resource/verb combination at all **PASSES**.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-cainjector
rules:
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["mutatingwebhookconfigurations", "validatingwebhookconfigurations"]
    verbs: ["get", "list", "watch", "update", "patch"]
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-cainjector
rules:
  # Read-only visibility retained; write access removed/delegated to a
  # narrowly-scoped, tightly audited role bound only to the cainjector
  # service account, or replaced with a controller mechanism that doesn't
  # require broad webhook-config write access.
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["mutatingwebhookconfigurations", "validatingwebhookconfigurations"]
    verbs: ["get", "list", "watch"]
```

## Remediation steps
1. Identify every `ClusterRoleBinding`/`RoleBinding` that binds this ClusterRole and confirm exactly which service accounts actually need write access to webhook configurations — for `cert-manager-cainjector`, this is expected (it patches CA bundles into existing webhook configs) but should be scoped to only that specific ServiceAccount and, if possible, only `patch` (not `create`/`update`) on pre-existing, named objects rather than blanket resource-type access.
2. Where the write access is legitimate (e.g., cert-manager's CA injector), verify you're running a current, trusted version of the component from a verified source, since it effectively holds cluster-wide config-injection power — treat compromise of that ServiceAccount as equivalent to broad cluster compromise.
3. For any ClusterRole flagged that does NOT need this permission, remove the `create`/`update`/`patch` verbs on these resources, or scope down to a `Role` in a single namespace if a namespaced `ValidatingWebhookConfiguration`/`MutatingWebhookConfiguration` equivalent applies (note these are cluster-scoped objects, so namespaced Roles cannot grant access to them at all — only ClusterRoles can).
4. Add monitoring/alerting on changes to `mutatingwebhookconfigurations`/`validatingwebhookconfigurations` objects cluster-wide (via audit logs) so any unexpected creation/modification is quickly detected regardless of RBAC posture.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/RbacControlWebhooks.py
- Kubernetes docs on admission webhooks: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
