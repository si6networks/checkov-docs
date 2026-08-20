# CKV_ANSIBLE_6: Ensure that the force parameter is not used with apt
## Severity
**LOW** (score: 2.0/10)

The apt force flag bypasses package signature validation and allows downgrades to known-vulnerable or tampered package versions, undermining the integrity of the software supply chain on managed hosts.

## Summary
This check ensures that Ansible `apt` tasks do not set `force: true`, since `force` bypasses package signature/authentication checks and allows package downgrades that can leave the system in a broken or inconsistent state.

## Applicability
**Checkov framework(s):** `ansible`

Applies to Ansible playbooks/roles, specifically any task using the `ansible.builtin.apt` module (or its short alias `apt`), including tasks nested inside `block:` structures up to four levels deep and tasks under `tasks:` blocks.

## Why it matters
The `force` parameter is passed through to the underlying `dpkg`/`apt-get` invocation as `--force-yes`-style behavior, which suppresses safety checks including package authentication and conflict resolution. This has two distinct risks: (1) security — it can allow installation of packages that fail GPG/signature verification, opening the same supply-chain attack surface as CKV_ANSIBLE_5 (malicious or tampered packages installed with root privileges); and (2) reliability — it permits downgrading packages to older, potentially vulnerable, or dependency-incompatible versions, which can silently reintroduce patched CVEs or corrupt the package database, leaving the host in an inconsistent, hard-to-recover state. Because this flag disables multiple safety nets at once, Debian/Ubuntu itself considers its use "dangerous" and discourages it outside of narrow recovery scenarios.

## How Checkov evaluates this
This is a Python check built on `BaseAnsibleTaskValueCheck`, configured for the `ansible.builtin.apt` / `apt` module. It inspects the task's `force` key, expecting the value `False`:
- If the key is **absent**, the check **PASSES** (`missing_block_result=CheckResult.PASSED`) since apt defaults to `force: false`.
- If `force` is explicitly set to `true`, the check **FAILS**.
- If explicitly set to `false`, the check **PASSES**.

## Non-compliant example
```yaml
- name: Force install/downgrade a package
  ansible.builtin.apt:
    name: openssl=1.1.1-1
    state: present
    force: true
```

## Remediated example
```yaml
- name: Install package without bypassing safety checks
  ansible.builtin.apt:
    name: openssl=1.1.1-1
    state: present
    force: false
```

## Remediation steps
1. Remove `force: true` from the `apt` task, or set it to `false`.
2. If a downgrade is genuinely required, pin the exact desired version via the `name: pkg=version` syntax and use `allow_downgrade: true` (a more explicit, narrowly-scoped option) instead of the blanket `force` flag.
3. If a conflict/authentication error is being suppressed, investigate and resolve the underlying dependency or signing issue rather than forcing through it.
4. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/task/builtin/AptForce.py)
- [Ansible apt module documentation](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/apt_module.html)
