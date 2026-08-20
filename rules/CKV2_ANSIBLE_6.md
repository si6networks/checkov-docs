# CKV2_ANSIBLE_6: Ensure that certificate validation isn't disabled with dnf

## Severity
**MEDIUM** (score: 5.0/10)

Disabling certificate validation for dnf removes protection against spoofed repository endpoints, enabling delivery of malicious packages and potential remote code execution.

## Summary
This check ensures that Ansible `dnf` module tasks do not disable certificate validation via the `validate_certs` option.

## Applicability
Ansible playbooks/roles. Applies to tasks using `ansible.builtin.dnf` or the legacy short module name `dnf`.

## Why it matters
`validate_certs` controls whether `dnf`'s underlying HTTP(S) client verifies the TLS certificate presented by the repository server. Setting `validate_certs: false` allows a network-positioned attacker to impersonate a trusted repository (via DNS spoofing, ARP poisoning, or a rogue proxy) without needing a certificate the client would otherwise reject. Once impersonating the repo, the attacker can serve malicious repository metadata or tampered packages, which — since dnf installs typically run with root privileges — can result in full host compromise. This is closely related to, but distinct from, the `sslverify` option checked by CKV2_ANSIBLE_5; some dnf/Ansible module versions expose both knobs.

## How Checkov evaluates this
This is a graph-based (JSON) policy. It inspects the `validate_certs` attribute of `tasks.ansible.builtin.dnf` / `tasks.dnf` tasks and requires it to **not equal `false`**. If `validate_certs: false` is set, the check **FAILS**. If the attribute is omitted (defaults to certificate validation being enabled) or explicitly `true`, the check **PASSES**.

## Non-compliant example
```yaml
- name: Install package with certificate validation disabled
  ansible.builtin.dnf:
    name: custom-tool
    state: present
    validate_certs: false
```

## Remediated example
```yaml
- name: Install package with certificate validation enabled
  ansible.builtin.dnf:
    name: custom-tool
    state: present
    validate_certs: true   # <-- fixed: keep certificate validation enabled (or omit this key)
```

## Remediation steps
1. Remove `validate_certs: false` from `dnf` tasks, or set it explicitly to `true`.
2. If the goal was to work around an untrusted/self-signed certificate on an internal mirror, add that CA to the managed host's trust store rather than disabling validation.
3. Check for and fix the same setting elsewhere (e.g. `get_url`, `uri`, `yum` tasks) since `validate_certs` is a common option name across multiple Ansible modules.
4. Confirm the fix doesn't break connectivity to legitimate internal repos that lack proper certificates — in that case, fix the certificate chain rather than suppressing the check.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/DnfValidateCerts.json
