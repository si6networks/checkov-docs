# CKV_K8S_153: Prevent All NGINX Ingress annotation snippets (CVE-2021-25742)
## Severity
**LOW** (score: 2.0/10)

Allowing any NGINX Ingress annotation snippets at all (CVE-2021-25742) lets anyone able to create an Ingress object inject arbitrary NGINX configuration/Lua that can read the controller's mounted secrets and pivot to cluster-wide compromise.

## Summary
This check flags any Kubernetes `Ingress` resource that uses **any** annotation whose key contains `snippet` (e.g., NGINX Ingress `configuration-snippet`, `server-snippet`, `stream-snippet`), regardless of the value's content, as a blanket prevention of the annotation-snippet feature implicated in CVE-2021-25742.

## Applicability
Kubernetes manifests of `kind: Ingress`. Inspects the `metadata.annotations` map for any key containing the substring `snippet`.

## Why it matters
This is the broader, stricter sibling of CKV_K8S_152: rather than only flagging snippets containing obviously dangerous Lua tokens, it flags the use of the snippet-annotation feature entirely. CVE-2021-25742 showed that in multi-tenant ingress-nginx deployments where `allow-snippet-annotations` is enabled, any user able to create or modify an `Ingress` resource in any namespace can inject raw NGINX (or Lua, in the OpenResty-based controller) configuration that gets compiled directly into the shared ingress controller's config and executed with the controller's privileges — enabling arbitrary code execution, disclosure of other tenants' TLS certificates/secrets, and access to the ingress controller's own service account credentials, which often have broad cluster read permissions. Because *any* snippet content — not just ones containing obviously malicious keywords — can be leveraged for injection depending on context and controller version, the safest posture is to disallow the snippet annotation mechanism altogether rather than trying to detect specific bad patterns within it, which is exactly the intent of this stricter check.

## How Checkov evaluates this
The check (`NginxIngressCVE202125742AllSnippets`) applies to `Ingress` resources:
1. It reads `metadata.annotations`.
2. If **any** annotation key contains the substring `"snippet"` — regardless of the value — the check **FAILS**.
3. If no annotations exist, or none of the keys contain `snippet`, the check **PASSES**.
This is a superset of CKV_K8S_152: any manifest failing 152 will also fail this check, but this check also fails on innocuous-looking snippet content that 152 would pass.

## Non-compliant example
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grafana-dev-redirect
  annotations:
    nginx.ingress.kubernetes.io/server-snippet: |
      location /internal {
        deny all;
      }
spec:
  rules:
    - host: grafana.dev.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: grafana
                port:
                  number: 80
```

## Remediated example
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grafana-dev-redirect
  annotations:
    nginx.ingress.kubernetes.io/permanent-redirect: https://grafana.example.com
    nginx.ingress.kubernetes.io/permanent-redirect-code: "301"
spec:
  rules:
    - host: grafana.dev.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: grafana
                port:
                  number: 80
```

## Remediation steps
1. Remove every annotation whose key contains `snippet` from `grafana-redirect.ingress.yaml` and `grafana-dev-redirect.ingress.yaml`.
2. Replace the functionality with a dedicated, purpose-built ingress-nginx annotation where one exists (e.g., `permanent-redirect`/`permanent-redirect-code` for redirects, `configuration-snippet` alternatives like `nginx.ingress.kubernetes.io/rewrite-target`, `auth-url`, `auth-snippet` replacements, etc.). If no built-in annotation covers the need, consider a dedicated NGINX `ConfigMap`-level customization managed by cluster admins rather than per-Ingress snippets.
3. At the controller level, set `allow-snippet-annotations: "false"` in the ingress-nginx controller ConfigMap so the annotation mechanism is disabled cluster-wide as defense in depth, independent of what individual manifests contain.
4. Upgrade ingress-nginx to a version with the CVE-2021-25742 fixes.
5. Audit all other Ingress objects in the repository (not just the two flagged files) for the same annotation pattern, since this is a blanket check and similar snippets may exist elsewhere.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/NginxIngressCVE202125742AllSnippets.py
- CVE-2021-25742: https://nvd.nist.gov/vuln/detail/CVE-2021-25742
