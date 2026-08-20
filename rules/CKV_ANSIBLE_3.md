# CKV_ANSIBLE_3: Ensure that certificate validation isn't disabled with yum
## Severity
**MEDIUM** (score: 5.0/10)

Disabling certificate validation for yum repository access exposes package installation to man-in-the-middle tampering, allowing an attacker to substitute malicious packages during provisioning.

## Summary
This check ensures that Ansible `yum` tasks do not explicitly disable TLS/SSL certificate validation when downloading packages or repository metadata.

## Applicability
Applies to Ansible playbooks/roles, specifically any task using the `ansible.builtin.yum` module (or its short alias `yum`), including tasks nested inside `block:` structures up to four levels deep and tasks under `tasks:` blocks.

## Why it matters
The `yum` module can fetch packages and repo metadata over HTTPS from configured repositories. If certificate validation is disabled, the module will trust any certificate presented by the server it connects to — including one supplied by an attacker performing a man-in-the-middle attack on the network path (e.g. a compromised mirror, DNS hijack, or rogue proxy). This allows an attacker to serve a trojaned RPM package or manipulated repository metadata that gets installed with root privileges on the managed host, resulting in full system compromise. Because package management runs with elevated privileges and is often automated/unattended, this is a particularly high-impact class of vulnerability in configuration management pipelines.

## How Checkov evaluates this
This is a Python check built on `BaseAnsibleTaskValueCheck`, configured for the `ansible.builtin.yum` / `yum` module. It inspects the task's `validate_certs` key:
- If the key is **absent**, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) since the module defaults to validating certificates.
- If `validate_certs` is explicitly set to a falsy value, the check **FAILS**.
- If `validate_certs` is explicitly set to `true`, the check **PASSES**.

## Non-compliant example
```yaml
- name: Install package without validating repo TLS certificate
  ansible.builtin.yum:
    name: httpd
    state: present
    validate_certs: false
```

## Remediated example
```yaml
- name: Install package with repo TLS certificate validation enabled
  ansible.builtin.yum:
    name: httpd
    state: present
    validate_certs: true
```

## Remediation steps
1. Remove `validate_certs: false` from the `yum` task, or set it to `true`.
2. If validation was disabled to work around an internal repository with a self-signed certificate, install the internal CA certificate into the system trust store on managed nodes instead of disabling validation.
3. Review any custom `.repo` files or repository definitions for similarly insecure settings (e.g. `sslverify=0`).
4. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/task/builtin/YumValidateCerts.py)
- [Ansible yum module documentation](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/yum_module.html)
