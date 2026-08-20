# CKV_K8S_156: Minimize ClusterRoles that grant permissions to approve CertificateSigningRequests
## Severity
**HIGH** (score: 7.5/10)

A ClusterRole permitted to approve CertificateSigningRequests can mint arbitrary client certificates (including for cluster-admin identities), a well-known Kubernetes privilege-escalation path to full cluster control.

## Summary
This check flags any `ClusterRole` that grants permission to approve `CertificateSigningRequest` objects — either via `update`/`patch` on the `certificatesigningrequests/approval` subresource or via `approve` on the `signers` resource in the `certificates.k8s.io` API group.

## Applicability
Kubernetes manifests of `kind: ClusterRole`. Inspects the role's `rules` for either of two failing patterns:
1. `apiGroups: [certificates.k8s.io]`, `verbs: [update, patch]`, `resources: [certificatesigningrequests/approval]`
2. `apiGroups: [certificates.k8s.io]`, `verbs: [approve]`, `resources: [signers]`

## Why it matters
Kubernetes' certificate-signing API (`CertificateSigningRequest`) lets any principal request a new client (or server) certificate for a given identity; the request is only actually usable once it's *approved* and *signed*. Whoever can approve CSRs effectively controls issuance of cluster identities — an attacker or over-privileged workload with this permission could approve a CSR requesting, for example, a client certificate impersonating `system:masters` or another highly privileged group/identity (subject to the signer's constraints), obtaining a valid, trusted certificate that authenticates as that identity to the API server. This is a direct privilege-escalation path: RBAC alone doesn't stop someone from *requesting* a CSR for an arbitrary identity, so the approval step (and which signer is used to actually issue the cert) is a critical control point. Because approval authority is this powerful, CIS-aligned hardening guidance (and Kubernetes' own security documentation) recommends minimizing which ClusterRoles/principals hold `approve` rights, especially for the built-in `kubernetes.io/kube-apiserver-client` signer which can issue certificates trusted for API server authentication.

## How Checkov evaluates this
The check (`RbacApproveCertificateSigningRequests`, extending `BaseRbacK8sCheck`) applies to `ClusterRole` resources and defines two "failing operation" patterns (either one matching is sufficient to fail):
1. `apiGroups: ["certificates.k8s.io"]`, `verbs: ["update", "patch"]`, `resources: ["certificatesigningrequests/approval"]` — write access to the approval subresource.
2. `apiGroups: ["certificates.k8s.io"]`, `verbs: ["approve"]`, `resources: ["signers"]` — the `approve` verb against specific/any signer(s), which since Kubernetes 1.18 is required in addition to the approval-subresource write to actually approve a CSR bound to that signer.

The base RBAC check logic examines each rule in the ClusterRole's `rules`; if any rule's `apiGroups`/`verbs`/`resources` overlap with either failing pattern, the check **FAILS**.

## Non-compliant example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: csr-approver
rules:
  - apiGroups: ["certificates.k8s.io"]
    resources: ["certificatesigningrequests/approval"]
    verbs: ["update", "patch"]
  - apiGroups: ["certificates.k8s.io"]
    resources: ["signers"]
    verbs: ["approve"]
    resourceNames: ["kubernetes.io/kube-apiserver-client"]
```

## Remediated example
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: csr-viewer
rules:
  # Read-only visibility into CSRs, no approval authority
  - apiGroups: ["certificates.k8s.io"]
    resources: ["certificatesigningrequests"]
    verbs: ["get", "list", "watch"]
```

## Remediation steps
1. Enumerate every `ClusterRoleBinding` that binds a role granting CSR-approval rights and confirm the bound identity (user/group/ServiceAccount) genuinely requires it — this is legitimately needed by very few components (e.g., the built-in `system:certificates.k8s.io:certificatesigningrequests:nodeclient` / kubelet-serving auto-approver controllers, or a deliberately built cert-management automation).
2. Remove the `update`/`patch` verb on `certificatesigningrequests/approval` and the `approve` verb on `signers` from any ClusterRole that doesn't have a specific, reviewed business need.
3. If automated approval is required (e.g., for kubelet client cert rotation, see CKV_K8S_149), scope the `signers` `resourceNames` as narrowly as possible (e.g., only `kubernetes.io/kubelet-serving`, never a bare `*` or the `kube-apiserver-client` signer) so the automation cannot mint certificates trusted for arbitrary/high-privilege authentication.
4. Enable audit logging on CSR approval events and alert on any approval action from an unexpected principal.
5. Regularly review outstanding and historical `CertificateSigningRequest` objects (`kubectl get csr`) for unexpected or unapproved requests, as an early indicator of an attempted privilege-escalation attempt.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/RbacApproveCertificateSigningRequests.py
- Kubernetes docs on CertificateSigningRequests: https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/
