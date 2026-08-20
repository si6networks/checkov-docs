# CKV_K8S_154: Prevent NGINX Ingress annotation snippets which contain alias statements (CVE-2021-25742)
## Severity
**LOW** (score: 2.0/10)

NGINX Ingress alias-based annotation snippets under CVE-2021-25742 let a low-privileged Ingress author redirect requests to arbitrary paths on the ingress controller's filesystem, exposing the controller's service-account token and other sensitive files.

## Summary
This check flags Kubernetes `Ingress` resources whose annotations contain a `*-snippet` key whose value includes the word `alias`, which can be used with NGINX's `alias` directive to break out of the intended web root and read arbitrary files from the ingress controller's filesystem.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests of `kind: Ingress`. Inspects the `metadata.annotations` map for keys containing `snippet` and values containing `alias`.

## Why it matters
As part of the CVE-2021-25742 disclosure, one specific and especially dangerous injection technique documented was using NGINX's `alias` directive inside an injected configuration snippet. Because `alias` maps a URI location directly to a filesystem path (rather than appending, as `root` does), a crafted snippet using `alias` combined with path traversal in the request can allow reading arbitrary files from the ingress controller pod's filesystem — including files like `/etc/ingress-controller/**` (which may contain other tenants' TLS private keys/certificates mounted into the shared controller) or other sensitive mounted secrets. This is a concrete file-disclosure/path-traversal primitive distinct from the general Lua code-execution risk (CKV_K8S_152) and the blanket snippet ban (CKV_K8S_153); this check specifically targets the `alias`-based file-read exploitation pattern.

## How Checkov evaluates this
The check (`NginxIngressCVE202125742Alias`) applies to `Ingress` resources:
1. It reads `metadata.annotations`.
2. For each annotation, if the key contains `"snippet"` **and** the value contains the substring `"alias"`, the check **FAILS**.
3. If no such combination is found, the check **PASSES**.

## Non-compliant example
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vulnerable-ingress
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: |
      location ~* "^/static/(?<path>.*)$" {
        alias /etc/ingress-controller/;
      }
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

## Remediated example
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: safe-ingress
  # no snippet annotations; static asset routing handled by the backend service
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /static
            pathType: Prefix
            backend:
              service:
                name: app-static-assets
                port:
                  number: 80
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

## Remediation steps
1. Remove any `*-snippet` annotation whose value uses the `alias` directive.
2. Move static-file-serving or path-remapping logic out of ingress annotations and into a properly configured backend Service/Deployment (e.g., a dedicated static-file server pod) so the ingress controller itself never needs filesystem `alias` mappings driven by tenant-controlled config.
3. Disable snippet annotations cluster-wide via `allow-snippet-annotations: "false"` in the ingress-nginx controller ConfigMap, and upgrade to a patched ingress-nginx release.
4. Review filesystem mounts on the ingress controller pod — minimize what sensitive paths (e.g., other tenants' certificate secrets) are even reachable via the controller's filesystem, as defense in depth against this class of vulnerability.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/NginxIngressCVE202125742Alias.py
- CVE-2021-25742: https://nvd.nist.gov/vuln/detail/CVE-2021-25742
