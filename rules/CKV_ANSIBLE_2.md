# CKV_ANSIBLE_2: Ensure that certificate validation isn't disabled with get_url
## Severity
**MEDIUM** (score: 5.0/10)

Disabling TLS certificate validation on get_url downloads lets a network-positioned attacker (MITM/DNS spoofing) serve a malicious payload that the target machine will download and potentially execute, risking remote code execution across managed nodes.

## Summary
This check ensures that Ansible `get_url` tasks do not explicitly disable TLS/SSL certificate validation, which would expose downloads to man-in-the-middle tampering.

## Applicability
Applies to Ansible playbooks/roles, specifically any task using the `ansible.builtin.get_url` module (or its short alias `get_url`), including tasks nested inside `block:` structures up to four levels deep and tasks under `tasks:` blocks.

## Why it matters
`get_url` is commonly used to fetch installers, binaries, packages, or configuration files over HTTP(S) as part of provisioning. If certificate validation is disabled (`validate_certs: false`), the module will accept any TLS certificate — valid, self-signed, expired, or attacker-supplied — when connecting to the download URL. An attacker positioned on the network path (compromised Wi-Fi, ARP/DNS spoofing, a rogue proxy, or a compromised CDN edge) can intercept the "secure" connection and serve a malicious payload that the target machine will download and potentially execute or install, resulting in remote code execution or supply-chain compromise. This is especially dangerous in automated provisioning pipelines, since a single compromised task can be replayed across an entire fleet of managed nodes.

## How Checkov evaluates this
This is a Python check built on `BaseAnsibleTaskValueCheck`, configured for the `ansible.builtin.get_url` / `get_url` module. It inspects the task's `validate_certs` key:
- If the key is **absent**, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) because `get_url`'s default behavior is to validate certificates.
- If `validate_certs` is explicitly set to a falsy value (e.g. `false`/`no`), the check **FAILS**.
- If `validate_certs` is explicitly set to `true`, the check **PASSES**.

## Non-compliant example
```yaml
- name: Download installer without validating TLS certificate
  ansible.builtin.get_url:
    url: https://downloads.example.com/installer.tar.gz
    dest: /opt/installer.tar.gz
    validate_certs: false
```

## Remediated example
```yaml
- name: Download installer with TLS certificate validation enabled
  ansible.builtin.get_url:
    url: https://downloads.example.com/installer.tar.gz
    dest: /opt/installer.tar.gz
    validate_certs: true
```

## Remediation steps
1. Remove `validate_certs: false` from the `get_url` task, or explicitly set it to `true`.
2. If the task was disabling validation to work around a self-signed/internal CA certificate, instead install the internal CA certificate on the managed node (or reference it via appropriate trust store configuration) rather than disabling validation entirely.
3. Audit any existing playbooks for similar patterns across other network-fetching modules (`uri`, `yum`, `apt`, etc.) since this class of misconfiguration tends to be copy-pasted.
4. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/task/builtin/GetUrlValidateCerts.py)
- [Ansible get_url module documentation](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/get_url_module.html)
