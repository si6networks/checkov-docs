# CKV2_ANSIBLE_3: Ensure block is handling task errors properly

## Severity
**LOW** (score: 2.5/10)

Lacking rescue-based error handling in a block is an operational reliability gap rather than a direct confidentiality or integrity exposure.

## Summary
This check ensures that Ansible `block` constructs include a `rescue` section so task failures inside the block are handled rather than causing an uncontrolled playbook failure.

## Applicability
**Checkov framework(s):** `ansible`

Ansible playbooks/roles. Applies to any `block` entity (a `block:` key grouping a list of tasks).

## Why it matters
`block`/`rescue`/`always` is Ansible's mechanism for structured error handling, analogous to try/catch/finally. Without a `rescue` clause, a failure partway through a block (e.g. a package install, a service restart, a config deployment) aborts the play on that host with no cleanup or compensating action, potentially leaving the system in a half-configured, inconsistent state — for example, a firewall rule removed but not replaced, a service stopped but not restarted, or a certificate rotated but not reloaded. In security- and availability-sensitive automation (patching, credential rotation, network ACL changes), an unhandled mid-block failure can leave a host in a more vulnerable or broken state than before the play ran, and without `rescue` there is no defined recovery/rollback path or opportunity to alert.

## How Checkov evaluates this
This is a graph-based (JSON) policy. It inspects each `block` resource and checks whether the `rescue` attribute **exists**. If a `block` has no `rescue:` key defined, the check **FAILS**. If `rescue` is present (regardless of what tasks it contains), the check **PASSES**.

## Non-compliant example
```yaml
- name: Rotate TLS certificate
  block:
    - name: Stop service
      ansible.builtin.service:
        name: nginx
        state: stopped

    - name: Deploy new certificate
      ansible.builtin.copy:
        src: new-cert.pem
        dest: /etc/nginx/ssl/cert.pem

    - name: Start service
      ansible.builtin.service:
        name: nginx
        state: started
```

## Remediated example
```yaml
- name: Rotate TLS certificate
  block:
    - name: Stop service
      ansible.builtin.service:
        name: nginx
        state: stopped

    - name: Deploy new certificate
      ansible.builtin.copy:
        src: new-cert.pem
        dest: /etc/nginx/ssl/cert.pem

    - name: Start service
      ansible.builtin.service:
        name: nginx
        state: started

  rescue:                                       # <-- fixed: handle failures
    - name: Restore previous certificate
      ansible.builtin.copy:
        src: cert.pem.bak
        dest: /etc/nginx/ssl/cert.pem

    - name: Ensure service is running
      ansible.builtin.service:
        name: nginx
        state: started

    - name: Notify on failure
      ansible.builtin.debug:
        msg: "Certificate rotation failed on {{ inventory_hostname }}, rolled back."
```

## Remediation steps
1. Add a `rescue:` section to every `block` that performs state-changing operations (service control, file writes, package management, security-relevant config changes).
2. In `rescue`, include compensating/rollback actions that return the host to a known-good state (e.g. restore backup, restart the stopped service) rather than leaving it mid-change.
3. Optionally add an `always:` section for cleanup/logging steps that must run whether the block succeeds or fails.
4. Use the special `ansible_failed_task` and `ansible_failed_result` variables inside `rescue` to log/report what actually failed, for observability.
5. For blocks that are read-only/idempotent (e.g. only gathering facts), a missing `rescue` is lower risk, but consider suppressing the finding or adding one anyway for consistency and future-proofing.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/ansible/checks/graph_checks/BlockErrorHandling.json
