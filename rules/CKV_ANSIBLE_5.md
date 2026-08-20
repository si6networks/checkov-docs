# CKV_ANSIBLE_5: Ensure that packages with untrusted or missing signatures are not used
## Severity
**LOW** (score: 2.0/10)

Allowing unauthenticated apt packages bypasses GPG signature verification entirely, letting an attacker who controls a mirror or the network path install arbitrary unsigned/tampered packages, a direct path to remote code execution.

## Summary
This check ensures that Ansible `apt` tasks do not set `allow_unauthenticated: true`, which would permit installing Debian/Ubuntu packages that lack a valid GPG signature.

## Applicability
Applies to Ansible playbooks/roles, specifically any task using the `ansible.builtin.apt` module (or its short alias `apt`), including tasks nested inside `block:` structures up to four levels deep and tasks under `tasks:` blocks.

## Why it matters
APT's package authentication relies on GPG signatures to guarantee that packages came from a trusted repository maintainer and were not tampered with in transit or at rest on a mirror. Setting `allow_unauthenticated: true` disables this check entirely, meaning apt will install any `.deb` package regardless of whether it is signed, correctly signed, or signed by a trusted key. An attacker who controls or compromises a mirror, performs a man-in-the-middle attack, or tricks the system into using a malicious repository can supply an arbitrary package that gets installed with root privileges — a direct path to full system compromise. This setting is sometimes enabled to work around broken/expired signing keys, which itself is a sign of an unmaintained or compromised repository and should be investigated rather than bypassed.

## How Checkov evaluates this
This is a Python check built on `BaseAnsibleTaskValueCheck`, configured for the `ansible.builtin.apt` / `apt` module. It inspects the task's `allow_unauthenticated` key, expecting the value `False`:
- If the key is **absent**, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) since apt defaults to requiring authenticated packages.
- If `allow_unauthenticated` is explicitly set to `true`, the check **FAILS**.
- If explicitly set to `false` (the expected value), the check **PASSES**.

## Non-compliant example
```yaml
- name: Install package allowing unsigned/untrusted packages
  ansible.builtin.apt:
    name: some-custom-package
    state: present
    allow_unauthenticated: true
```

## Remediated example
```yaml
- name: Install package requiring authenticated packages
  ansible.builtin.apt:
    name: some-custom-package
    state: present
    allow_unauthenticated: false
```

## Remediation steps
1. Remove `allow_unauthenticated: true` from the `apt` task, or set it to `false`.
2. If a custom repository's packages are failing signature verification, import and trust the repository's actual signing key (e.g. via `ansible.builtin.apt_key` or the newer `signed-by` keyring mechanism) rather than disabling verification.
3. Investigate why authentication is failing before removing the flag — it can indicate a broken build pipeline, an expired key, or an actively compromised mirror.
4. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/task/builtin/AptAllowUnauthenticated.py)
- [Ansible apt module documentation](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/apt_module.html)
