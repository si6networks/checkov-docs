# CKV2_DOCKER_1: Ensure that sudo isn't used

## Severity
**LOW** (score: 2.0/10)

Invoking sudo inside a Dockerfile RUN step signals unnecessary privilege escalation during image build and often indicates broader use of root-level operations in the resulting image, increasing the blast radius if the image or build process is compromised.

## Summary
This check verifies that no `RUN` instruction in a Dockerfile invokes `sudo`, since containers should not need privilege-escalation tooling baked into the image.

## Applicability
- **Dockerfile**: any `RUN` instruction.

This is a graph-based check that pattern-matches the literal text of `RUN` instruction values.

## Why it matters
`sudo` inside a Dockerfile is almost always unnecessary and often actively harmful: Docker build steps already run as whatever user is active in the current build stage (root by default), so `sudo` adds no functional capability — it only adds an extra binary and, frequently, an interactive-password or NOPASSWD sudoers configuration to the image. Baking `sudo` and a sudoers file into a runtime image expands the attack surface if an attacker gains a foothold in the container: a misconfigured or overly permissive sudoers entry could let a low-privilege process regain root inside the container, defeating an otherwise-intentional "run as non-root" design. It's also a strong signal that the Dockerfile was adapted from an interactive host/VM setup script rather than designed for containers, which often carries other anti-patterns (unpinned packages, unnecessary interactive tooling, larger attack surface/image size).

## How Checkov evaluates this
The check is a JSON graph query, not Python. It inspects the literal `value` (i.e., the full shell command string) of every `RUN` instruction:

- FAIL: the `RUN` command string contains `" sudo "` (sudo preceded and followed by whitespace, i.e. used mid-command) **or** the command string starts with `"sudo "`.
- PASS: neither pattern matches — i.e., `sudo` does not appear as its own token anywhere in the run command.

Because this is a simple substring/prefix check (not a true tokenizer), it can be fooled by unusual spacing but will catch the vast majority of real-world usages, including chained commands like `apt-get update && sudo apt-get install -y foo`.

## Non-compliant example
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && sudo apt-get install -y curl vim
```

## Remediated example
```dockerfile
FROM ubuntu:22.04

# Removed sudo: build-time RUN already executes as root (or the active USER)
RUN apt-get update && apt-get install -y curl vim
```

## Remediation steps
1. Remove `sudo` from every `RUN` instruction — build steps execute with the privileges of the current `USER` (root by default), so `sudo` is redundant during image build.
2. If a `USER` directive earlier in the Dockerfile has already dropped privileges and a later step genuinely needs root for setup, restructure the Dockerfile so privileged setup happens before `USER` is switched to non-root, rather than using `sudo` after the fact.
3. Do not install the `sudo` package in the final image at all unless there is a specific, reviewed operational reason (e.g., an interactive debugging image) — it is unnecessary attack surface in a production runtime image.
4. Audit any base images inherited from internal templates that historically included `sudo` for interactive/VM-style setup and remove that pattern from the shared template, not just this one Dockerfile.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunUsingSudo.json)
