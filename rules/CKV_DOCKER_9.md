# CKV_DOCKER_9: Ensure that APT isn't used

## Severity
**LOW** (score: 2.0/10)

Preferring apt-get over apt is a tooling-stability best practice (apt's CLI is not guaranteed stable for scripting) rather than a control that mitigates a specific security threat.

## Summary
This check flags Dockerfile `RUN` instructions that invoke the `apt` command-line tool directly, recommending `apt-get` (or `apt-cache`) instead, because `apt`'s interface is not guaranteed stable across Debian/Ubuntu releases.

## Applicability
- **IaC framework**: Dockerfile
- **Instruction inspected**: `RUN`
- Applies to any `RUN` instruction whose shell command invokes `apt` as a standalone word.

## Why it matters
`apt` is designed and documented by Debian as an interactive, end-user-facing convenience wrapper around `apt-get`/`apt-cache`/`apt-config`. Debian's own release notes explicitly warn that `apt`'s command-line interface and output format are **not stable** and may change between releases without notice, specifically to discourage scripting against it. Using it in a Dockerfile build step creates several problems:

- **Non-reproducible builds**: A `RUN apt install ...` step that works today may emit different output, prompts, or exit-code behavior after the base image is rebuilt against a newer Debian/Ubuntu release, breaking automated, non-interactive CI/CD image builds in ways that are hard to diagnose.
- **Silent failures in automation**: `apt`'s progress bars and colorized/interactive output are more likely to cause parsing issues or hangs in non-TTY build environments compared to `apt-get`, which is explicitly designed for scripting.
- **Inconsistent security patching**: If build automation silently fails to install packages (including security updates) because of an `apt` interface change, the resulting image may ship without patches its Dockerfile appeared to include, giving a false sense of currency.

## How Checkov evaluates this
The check (`RunUsingAPT`) inspects the shell content of each `RUN` instruction:
1. It splits the command content on `&&` into individual sub-commands.
2. For each sub-command, it checks whether the substring `" apt "` (space-delimited, so it won't match `apt-get`) appears **and** the sub-command does not also contain `"rm"` (an allowance for cleanup commands like `rm -rf /var/lib/apt/lists/*` that may legitimately reference the `apt` directory/lists path without invoking the tool).
3. **FAILS** as soon as one such sub-command is found.
4. **PASSES** if no `RUN` instruction matches this pattern.

## Non-compliant example
```dockerfile
FROM debian:12-slim

RUN apt update && apt install -y curl ca-certificates
```

## Remediated example
```dockerfile
FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
```

## Remediation steps
1. Replace every scripted `apt <subcommand>` invocation in `RUN` instructions with the corresponding stable command: `apt-get update`, `apt-get install`, `apt-get remove`, etc.
2. Use `apt-cache` instead of `apt search`/`apt show` for query operations in scripts.
3. Keep `apt` (the tool) reserved for humans running the container interactively; never rely on it inside Dockerfiles or other automated scripts.
4. While remediating, also consider adding `--no-install-recommends` and cleaning the apt cache (`rm -rf /var/lib/apt/lists/*`) in the same `RUN` layer to reduce image size and attack surface — this is unrelated to the check itself but a common companion improvement.
5. Re-scan with Checkov to confirm no `RUN` instruction contains a bare `apt` invocation outside of an `rm`-related cleanup command.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/RunUsingAPT.py
- Debian Wiki on apt vs apt-get: https://wiki.debian.org/Apt
