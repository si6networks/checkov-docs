# CKV2_ANSIBLE_5: Ensure that SSL validation isn't disabled with dnf

## Severity
**MEDIUM** (score: 5.0/10)

Disabling SSL verification for dnf repository connections enables man-in-the-middle attacks that can substitute malicious packages, risking code execution on the managed host.

## Summary
This check ensures that Ansible `dnf` module tasks do not disable SSL/TLS certificate validation when connecting to package repositories.

## Applicability
Ansible playbooks/roles. Applies to tasks using `ansible.builtin.dnf` or the legacy short module name `dnf`.

## Why it matters
When `dnf` fetches package metadata and RPMs over HTTPS, SSL validation (`sslverify`) confirms that it is actually talking to the legitimate repository server and not an impersonator. Setting `sslverify: false` disables that check, allowing a man-in-the-middle attacker (on a compromised network, malicious proxy, or DNS-hijacked path) to serve a fake repository or malicious packages while presenting any certificate — valid or not. Combined with a lack of GPG verification, this can lead directly to arbitrary code execution on the host via a tampered package. Even with GPG verification still enabled, disabling SSL validation weakens defense-in-depth and can expose metadata to tampering/downgrade attacks.

## How Checkov evaluates this
This is a graph-based (JSON) policy. It inspects the `sslverify` attribute of `tasks.ansible.builtin.dnf` / `tasks.dnf` tasks and requires it to **not equal `false`**. If `sslverify: false` is set, the check **FAILS**. If the attribute is omitted (dnf's default is to verify) or explicitly `true`, the check **PASSES**.

## Non-compliant example
```yaml
- name: Install package with SSL verification disabled
  ansible.builtin.dnf:
    name: custom-tool
    state: present
    sslverify: false
```

## Remediated example
```yaml
- name: Install package with SSL verification enabled
  ansible.builtin.dnf:
    name: custom-tool
    state: present
    sslverify: true   # <-- fixed: keep certificate validation enabled (or omit this key)
```

## Remediation steps
1. Remove `sslverify: false` from `dnf` tasks, or set it explicitly to `true`.
2. If disabling was a workaround for an internal repo with a self-signed or untrusted certificate, install that CA's certificate into the host's trust store (e.g. via `ansible.builtin.copy` + `update-ca-trust`) instead of bypassing validation entirely.
3. Ensure the repository's `.repo` configuration (`sslverify=1`) matches — some environments set this at both the module-task level and the repo-definition level.
4. Audit playbooks for the equivalent setting on the `yum` module and on any custom `.repo` files deployed to hosts.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/DnfSslVerify.json
