# CKV2_ANSIBLE_4: Ensure that packages with untrusted or missing GPG signatures are not used by dnf

## Severity
**MEDIUM** (score: 5.0/10)

Disabling GPG signature checks for dnf packages allows installation of unsigned or tampered packages, creating a direct path to remote code execution via a compromised repository or MITM.

## Summary
This check ensures that Ansible `dnf` module tasks do not disable GPG signature verification when installing packages.

## Applicability
**Checkov framework(s):** `ansible`

Ansible playbooks/roles. Applies to tasks using `ansible.builtin.dnf` or the legacy short module name `dnf`.

## Why it matters
GPG signature verification on RPM packages guarantees that a package was published by a trusted repository maintainer and has not been tampered with in transit or by a compromised mirror. Setting `disable_gpg_check: true` (or omitting protections) turns off this check, meaning `dnf` will happily install any RPM handed to it — including one injected by a man-in-the-middle, a compromised package mirror, or a malicious internal repository — potentially leading to arbitrary code execution with root privileges during package installation (RPM `%post` scriptlets run as root). This is a supply-chain integrity control, and disabling it removes a key defense against tampered packages.

## How Checkov evaluates this
This is a graph-based (JSON) policy. It inspects the `disable_gpg_check` attribute of `tasks.ansible.builtin.dnf` / `tasks.dnf` tasks and requires it to **not equal `true`**. If `disable_gpg_check: true` is set, the check **FAILS**. If the attribute is absent (the Ansible/dnf default is GPG checking enabled) or explicitly set to `false`, the check **PASSES**.

## Non-compliant example
```yaml
- name: Install package from internal repo
  ansible.builtin.dnf:
    name: custom-tool
    state: present
    disable_gpg_check: true
```

## Remediated example
```yaml
- name: Install package from internal repo
  ansible.builtin.dnf:
    name: custom-tool
    state: present
    disable_gpg_check: false   # <-- fixed: keep GPG verification enabled (or simply omit this key)
```

## Remediation steps
1. Remove `disable_gpg_check: true` from `dnf` tasks, or set it explicitly to `false`.
2. If the underlying reason for disabling GPG checking is that the internal repo's packages are unsigned, sign the packages/repo instead (e.g. with `rpm --addsign` and a proper GPG key) and import the trusted key on managed hosts via `ansible.builtin.rpm_key`.
3. Add the repository's GPG key to the host's trusted keyring before running the `dnf` task (`rpm_key` module or `.repo` file `gpgkey=` field), rather than bypassing verification.
4. Audit any existing playbooks/roles for `disable_gpg_check` usage across all `dnf`/`yum` tasks, since the same risk pattern applies to the `yum` module as well.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/DnfDisableGpgCheck.json
