# CKV2_DOCKER_11: Ensure that the '--force-yes' option is not used

## Severity
**HIGH** (score: 7.5/10)

The apt-get --force-yes flag disables package signature validation and permits downgrades, allowing installation of unauthenticated or intentionally vulnerable package versions during image build.

## Summary
This check verifies that `apt-get` invocations in a Dockerfile do not use the `--force-yes` flag, which disables package signature validation and allows downgrades/broken installs.

## Applicability
**Checkov framework(s):** `dockerfile`

- **Dockerfile**: any `RUN` instruction.

This is a graph-based check using regex matching against the `RUN` instruction's command text.

## Why it matters
`apt-get --force-yes` is a deprecated Debian/Ubuntu flag (removed entirely in newer `apt`/`apt-get` versions in favor of more explicit `--allow-*` flags) that tells the package manager to proceed even when it would normally refuse — including installing packages whose GPG signatures cannot be verified, downgrading packages to older, potentially vulnerable versions, and overriding other package-integrity safety checks. Using it in a Dockerfile means a compromised or misconfigured APT mirror could silently deliver a tampered or outdated package, and the build would install it without any signature-based defense. It is a strong "unsafe automation" smell: it typically appears because a build script hit an interactive confirmation or signature failure and someone forced past it, rather than fixing the underlying repository/key configuration.

## How Checkov evaluates this
The check is a JSON graph query using a `not_regex_match` operator against the `RUN` instruction's `value`:

- FAIL: the command text matches `apt-get ... --force-yes` (an `apt-get` invocation, not immediately terminated by a pipe/`&`/`;`, using `--force-yes`).
- PASS: no `apt-get` command in the `RUN` instruction uses `--force-yes`.

## Non-compliant example
```dockerfile
FROM debian:11

RUN apt-get update && apt-get install --force-yes -y some-package
```

## Remediated example
```dockerfile
FROM debian:11

# Removed --force-yes: package signatures are verified normally
RUN apt-get update && apt-get install -y some-package
```

## Remediation steps
1. Remove `--force-yes` from every `apt-get` invocation.
2. If the underlying issue is an untrusted/unsigned repository, add and trust the repository's proper GPG key (`apt-key add` or, preferably, a keyring file referenced via `signed-by` in the sources list) instead of forcing past the failure.
3. If the underlying issue is a version conflict or intentional downgrade, use `apt-get install <package>=<version>` with an explicit, reviewed version pin rather than a blanket override flag.
4. On modern APT versions, `--force-yes` is a no-op/removed entirely — if the Dockerfile depends on it functioning, that is itself a sign the base image or command needs to be updated to current APT syntax (`--allow-downgrades`, `--allow-unauthenticated`, used sparingly and deliberately if ever needed).

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunAptGetForceYes.json)
