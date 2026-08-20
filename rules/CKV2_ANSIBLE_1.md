# CKV2_ANSIBLE_1: Ensure that HTTPS url is used with uri

## Severity
**MEDIUM** (score: 5.5/10)

Allowing non-HTTPS URLs with the uri module exposes requests to interception and tampering (man-in-the-middle), risking credential or data exposure in transit.

## Summary
This check ensures that Ansible `uri` module tasks only fetch URLs over HTTPS, not plaintext HTTP or other insecure schemes.

## Applicability
Ansible playbooks/roles. Applies to tasks using `ansible.builtin.uri` or the legacy short module name `uri`.

## Why it matters
The `uri` module is frequently used in playbooks to call web APIs, download metadata, perform health checks, or trigger webhooks — often carrying authentication tokens, API keys, or other secrets in headers, query strings, or bodies. If the URL is not HTTPS, all of that traffic (request and response) travels in plaintext and can be intercepted or tampered with by any on-path attacker (compromised network segment, malicious proxy, ARP spoofing, etc.), a classic man-in-the-middle exposure. This is especially risky in CI/CD runners and cloud environments where network paths are shared or less trusted.

## How Checkov evaluates this
This is a graph-based (JSON) policy. It inspects the `url` attribute of any `tasks.ansible.builtin.uri` or `tasks.uri` task and checks whether the string **starts with** `https://`. If the value does not start with `https://` (e.g. it starts with `http://`, uses a variable that resolves at runtime, or omits the scheme), the check **FAILS**. Only an explicit `https://` prefix **PASSES**.

## Non-compliant example
```yaml
- name: Query internal API
  ansible.builtin.uri:
    url: "http://internal-api.example.com/v1/status"
    method: GET
    headers:
      Authorization: "Bearer {{ api_token }}"
```

## Remediated example
```yaml
- name: Query internal API
  ansible.builtin.uri:
    url: "https://internal-api.example.com/v1/status"   # <-- fixed: HTTPS
    method: GET
    headers:
      Authorization: "Bearer {{ api_token }}"
```

## Remediation steps
1. Change the `url` field of every `uri`/`ansible.builtin.uri` task to use the `https://` scheme.
2. If the target endpoint truly does not support TLS, consider whether it should — many internal services can be placed behind a TLS-terminating proxy or load balancer instead.
3. If the URL is built from a variable (e.g. `"{{ base_url }}/path"`), ensure the variable's default/documented value uses `https://`, and validate at variable-definition time rather than relying on this check catching it downstream.
4. For endpoints using self-signed certificates, prefer providing a CA bundle via `ca_path`/`validate_certs` tuning rather than falling back to HTTP.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/UriHttpsOnly.json
