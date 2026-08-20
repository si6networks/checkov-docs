# CKV_ANSIBLE_4: Ensure that SSL validation isn't disabled with yum
## Severity
**MEDIUM** (score: 5.0/10)

Disabling SSL verification (sslverify) for yum has the same effect as disabling certificate validation, letting an attacker on the network path inject tampered packages during installation.

## Summary
This check ensures that Ansible `yum` tasks do not disable SSL verification of the repository server via the `sslverify` parameter.

## Applicability
**Checkov framework(s):** `ansible`

Applies to Ansible playbooks/roles, specifically any task using the `ansible.builtin.yum` module (or its short alias `yum`), including tasks nested inside `block:` structures up to four levels deep and tasks under `tasks:` blocks.

## Why it matters
This is a companion check to CKV_ANSIBLE_3, but targets the distinct `sslverify` parameter of the `yum` module rather than `validate_certs`. YUM repository configuration allows disabling SSL peer verification at connection time via `sslverify`. If disabled, the client will accept any TLS certificate from a repo mirror, meaning an attacker able to intercept or redirect traffic to the yum repository endpoint (DNS spoofing, compromised network path, malicious mirror) can serve tampered packages or repository metadata that get installed with root privileges. This undermines the entire chain-of-trust that package signing and HTTPS transport are meant to provide, and can lead to full remote code execution on the managed host.

## How Checkov evaluates this
This is a Python check built on `BaseAnsibleTaskValueCheck`, configured for the `ansible.builtin.yum` / `yum` module. It inspects the task's `sslverify` key:
- If the key is **absent**, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) because the module defaults to verifying SSL.
- If `sslverify` is explicitly set to a falsy value, the check **FAILS**.
- If `sslverify` is explicitly set to `true`, the check **PASSES**.

## Non-compliant example
```yaml
- name: Install package without SSL verification of repo
  ansible.builtin.yum:
    name: nginx
    state: latest
    sslverify: false
```

## Remediated example
```yaml
- name: Install package with SSL verification of repo enabled
  ansible.builtin.yum:
    name: nginx
    state: latest
    sslverify: true
```

## Remediation steps
1. Remove `sslverify: false` from the `yum` task, or set it to `true`.
2. If the setting was disabled due to certificate issues with an internal repo mirror, fix the mirror's certificate (proper chain, correct hostname/SAN) or add the internal CA to the trust store, instead of disabling verification.
3. Check whether `validate_certs` (CKV_ANSIBLE_3) is also disabled on the same or related tasks — these are frequently misconfigured together.
4. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/task/builtin/YumSslVerify.py)
- [Ansible yum module documentation](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/yum_module.html)
