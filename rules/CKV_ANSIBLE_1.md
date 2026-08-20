# CKV_ANSIBLE_1: Ensure that certificate validation isn't disabled with uri
## Severity
**MEDIUM** (score: 5.0/10)

Disabling TLS certificate validation on an Ansible uri task allows man-in-the-middle attackers to intercept or tamper with HTTPS traffic used for provisioning, including credentials and secrets.

## Summary
This check ensures that Ansible tasks using the `uri` (or `ansible.builtin.uri`) module do not disable TLS certificate validation by setting `validate_certs: false`.

## Applicability
**Checkov framework(s):** `ansible`

- **Framework:** Ansible
- **Task/module scope:** any task invoking `ansible.builtin.uri` or its short alias `uri`, including tasks nested inside `block:` sections up to several levels deep, and both at the play `tasks:` level and standalone task-file level (per the JMESPath entity selectors covering `tasks`, `block`, and nested `block` combinations).

## Why it matters
The `uri` module is commonly used in Ansible playbooks to call REST APIs, download artifacts, perform health checks, or interact with webhook endpoints — often over HTTPS with credentials, tokens, or sensitive payloads in the request. When `validate_certs` is set to `false`, the module accepts any TLS certificate presented by the remote server, including self-signed, expired, or attacker-forged certificates. This completely defeats the purpose of TLS's server-authentication guarantee and opens the automation run to man-in-the-middle attacks: an attacker positioned on the network path (e.g., via ARP spoofing, a compromised DNS resolver, or a rogue Wi-Fi access point in a CI runner environment) can transparently intercept and modify the request/response, capturing embedded API tokens or credentials and potentially injecting malicious responses that the playbook then acts upon. Because Ansible automation frequently runs with elevated privileges against production infrastructure, a compromised `uri` call can have outsized blast radius compared to a similar issue in an end-user application.

## How Checkov evaluates this
This is a `BaseAnsibleTaskValueCheck` (a specialization for Ansible task modules) configured for the `ansible.builtin.uri`/`uri` module, inspecting the `validate_certs` key within the task's module arguments.
- **Missing key:** treated as **PASSED** (`missing_block_result=CheckResult.PASSED`) — the module's own secure default (`validate_certs: true`) is trusted when the key is simply omitted.
- **FAIL** if `validate_certs` is explicitly set to `false` (or a falsy equivalent such as `no`).
- **PASS** if `validate_certs` is omitted, or explicitly set to `true`/`yes`.

## Non-compliant example
```yaml
- name: Call internal API
  ansible.builtin.uri:
    url: https://api.internal.example.com/v1/status
    method: GET
    validate_certs: false   # disables TLS certificate validation
  register: result
```

## Remediated example
```yaml
- name: Call internal API
  ansible.builtin.uri:
    url: https://api.internal.example.com/v1/status
    method: GET
    validate_certs: true    # <-- changed: TLS certificate validation enforced
  register: result
```

## Remediation steps
1. Remove `validate_certs: false` from the task, or set it explicitly to `true`.
2. If the target endpoint uses a self-signed or internal-CA certificate that legitimately fails default validation, install/trust the internal CA certificate on the Ansible control node (or target host, depending on execution context) instead of disabling validation outright.
3. For endpoints under active development/testing only, scope any temporary `validate_certs: false` usage tightly (e.g., behind a variable defaulting to `true`, only overridden in an isolated test inventory) and never let it reach production playbooks.
4. Audit any roles/collections pulled from external sources for the same pattern, since third-party roles are a common source of this misconfiguration being inherited silently.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/task/builtin/UriValidateCerts.py)
- [Ansible `uri` module documentation](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/uri_module.html)
