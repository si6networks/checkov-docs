# CKV_K8S_152: Prevent NGINX Ingress annotation snippets which contain LUA code execution (CVE-2021-25742)
## Severity
**LOW** (score: 2.0/10)

Permitting Lua code in NGINX Ingress annotation snippets enables CVE-2021-25742, which allows arbitrary Lua/code execution in the ingress controller and can lead to full disclosure of controller service-account secrets and cluster compromise.

## Summary
This check flags Kubernetes `Ingress` resources whose annotations contain a `*-snippet` key (e.g., `nginx.ingress.kubernetes.io/configuration-snippet`) whose value includes Lua-related keywords or the `kubernetes.io` string, which could be used to inject and execute arbitrary Lua/config code in the NGINX ingress controller.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests of `kind: Ingress`. Inspects the `metadata.annotations` map for keys containing `snippet` and their values.

## Why it matters
NGINX Ingress Controller historically allowed arbitrary configuration snippets to be injected via annotations such as `nginx.ingress.kubernetes.io/configuration-snippet`, `server-snippet`, etc. CVE-2021-25742 documented that, in multi-tenant clusters where the `allow-snippet-annotations` feature was enabled and different teams/tenants could create their own `Ingress` objects, a low-privileged user able to create/modify Ingress resources could inject snippet annotations that get embedded directly into the shared NGINX controller's configuration and, in the Lua-enabled build of the controller (OpenResty/`ngx.lua` used by ingress-nginx), execute arbitrary Lua code within the ingress controller pod — a privilege escalation from "can create an Ingress in my own namespace" to "can execute code in the shared, cluster-wide ingress controller," potentially exposing other tenants' TLS secrets, backend service credentials, or the controller's own service account token. This check specifically targets snippet values containing Lua-related tokens (`lua_`, `_lua`, `_lua_`) or references to `kubernetes.io` (which can appear in crafted payloads referencing internal APIs/paths) as signatures of an attempted exploit or a dangerous pattern matching this CVE class.

## How Checkov evaluates this
The check (`NginxIngressCVE202125742Lua`) applies to `Ingress` resources and uses the regex `BAD_INJECTION_PATTERN = r"\blua_|_lua\b|_lua_|\bkubernetes\.io\b"`:
1. It reads `metadata.annotations`.
2. For each annotation key/value pair, if the key contains the substring `"snippet"` **and** the value matches `BAD_INJECTION_PATTERN` (i.e., contains a Lua-related token boundary or the literal `kubernetes.io`), the check **FAILS**.
3. If no annotation matches, or there are no annotations, the check **PASSES**.

## Non-compliant example
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grafana-dev-redirect
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: |
      access_by_lua_block {
        ngx.exit(ngx.HTTP_FORBIDDEN)
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
1. Remove any `*-snippet` annotations (e.g., `configuration-snippet`, `server-snippet`, `stream-snippet`) that contain Lua directives or other injected config logic; use built-in, purpose-specific ingress-nginx annotations instead (e.g., `permanent-redirect`, `rewrite-target`, `auth-*` annotations) which cover most legitimate use cases without arbitrary code injection.
2. Upgrade ingress-nginx to a patched version (>= the fix versions for CVE-2021-25742) and, on multi-tenant clusters, set `allow-snippet-annotations: "false"` in the controller's ConfigMap to disable snippet annotations globally regardless of individual Ingress content.
3. If snippets are genuinely required for a specific legitimate use case, restrict who can create/edit `Ingress` objects via RBAC, and consider validating admission (e.g., OPA/Gatekeeper or Kyverno policy) to block snippet annotations from non-trusted namespaces/users.
4. Re-scan all Ingress objects across the cluster after remediation, not just the flagged example, since snippet-based patterns can be reused across many Ingress definitions.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/NginxIngressCVE202125742Lua.py
- CVE-2021-25742: https://nvd.nist.gov/vuln/detail/CVE-2021-25742
