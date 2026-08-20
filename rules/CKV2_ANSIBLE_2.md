# CKV2_ANSIBLE_2: Ensure that HTTPS url is used with get_url

## Severity
**MEDIUM** (score: 5.5/10)

Fetching files over plain HTTP/FTP with get_url allows a network attacker to tamper with or substitute downloaded content, but exploitation requires an active MITM position and impact depends on how the fetched artifact is used.

## Summary
This check ensures that Ansible `get_url` module tasks download files only over HTTPS, disallowing plaintext HTTP and FTP URLs.

## Applicability
Ansible playbooks/roles. Applies to tasks using `ansible.builtin.get_url` or the legacy short module name `get_url`.

## Why it matters
`get_url` is commonly used to download installers, binaries, packages, or configuration files onto managed hosts. If the download URL uses `http://` or `ftp://`, the transfer is unauthenticated and unencrypted: an on-path attacker can substitute the downloaded artifact with a malicious payload (a classic software-supply-chain attack), and there's no way for the client to verify the server's identity or the integrity of the transport. Because `get_url` output is frequently executed or installed with elevated privileges (e.g. installer scripts run as root), a tampered download can lead directly to remote code execution on the managed host.

## How Checkov evaluates this
This is a graph-based (JSON) policy that combines two attribute conditions with AND on `tasks.ansible.builtin.get_url` / `tasks.get_url`:
1. `url` must **not start with** `http://`
2. `url` must **not start with** `ftp://`

If either the `http://` or `ftp://` prefix is found on the `url` field, the check **FAILS**. Any other scheme (in practice, `https://`) **PASSES**. Note this is a blocklist of two specific prefixes rather than a strict "must start with https://" allowlist, but in practice `https://` is the only URL scheme that will satisfy both conditions for typical download URLs.

## Non-compliant example
```yaml
- name: Download installer package
  ansible.builtin.get_url:
    url: "http://downloads.example.com/tools/installer.sh"
    dest: /tmp/installer.sh
    mode: '0755'
```

## Remediated example
```yaml
- name: Download installer package
  ansible.builtin.get_url:
    url: "https://downloads.example.com/tools/installer.sh"   # <-- fixed: HTTPS
    dest: /tmp/installer.sh
    mode: '0755'
    checksum: "sha256:abcdef1234...."   # recommended: verify integrity too
```

## Remediation steps
1. Change every `get_url` task's `url` to use `https://` instead of `http://` or `ftp://`.
2. If the source only offers FTP, mirror the artifact to an internal HTTPS-served repository/artifact store, or switch to `sftp`/`ftps` with an appropriate Ansible module.
3. Add a `checksum` parameter to `get_url` to verify file integrity independent of transport security — defense in depth against a compromised or mis-configured HTTPS endpoint.
4. For internal/private mirrors without public certificates, issue them proper TLS certs (e.g. via an internal CA) rather than reverting to HTTP.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/GetUrlHttpsOnly.json
