# CKV_DOCKER_10: Ensure that WORKDIR values are absolute paths

## Severity
**LOW** (score: 2.0/10)

A relative WORKDIR is a build-portability and clarity issue with no direct exploitability of its own.

## Summary
This check fails a Dockerfile if any `WORKDIR` instruction uses a relative path instead of an absolute path (or a recognized variable/Windows-drive form).

## Applicability
Dockerfiles — specifically the `WORKDIR` instruction.

## Why it matters
`WORKDIR` sets the working directory for all subsequent `RUN`, `CMD`, `ENTRYPOINT`, `COPY`, and `ADD` instructions in that build stage. If a relative `WORKDIR` is used, its actual resolved location depends on whatever the *previous* working directory was (which could be the image's default, or the last absolute `WORKDIR` set earlier in the file, or nothing at all if it's the first instruction). This makes the effective filesystem location non-obvious just from reading the instruction, increases the chance of files being copied to or executed from an unintended path, and makes the Dockerfile fragile to reordering or to being copy-pasted into another file with a different base image (where the implicit prior working directory differs). While primarily a reliability/predictability issue, unpredictable file placement inside a container has downstream security implications too — e.g., increasing the odds that permissions, `COPY --chown` targets, or volume mounts land somewhere other than intended, and making it harder to reason about (and audit) exactly what's on the filesystem where.

## How Checkov evaluates this
The check (`WorkdirIsAbsolute`) applies the regex `^"?((/[A-Za-z0-9-_+]*)|([A-Za-z0-9-_+]:\\.*)|(\$[{}A-Za-z0-9-_+].*))` against each `WORKDIR` instruction's value. This matches values that: start with `/` (Unix absolute path), match a Windows-style drive path (`C:\...`), or start with a variable reference (`$VAR` or `${VAR}`, since a variable might expand to an absolute path). If a `WORKDIR` value does not match this pattern, it is collected as a failing instruction. If one or more `WORKDIR` instructions fail the pattern, the check FAILS (reporting each offending instruction); if all `WORKDIR` values match, it PASSES.

## Non-compliant example
```dockerfile
FROM node:20-slim

WORKDIR app
COPY . .
RUN npm ci

CMD ["node", "server.js"]
```

## Remediated example
```dockerfile
FROM node:20-slim

WORKDIR /app
COPY . .
RUN npm ci

CMD ["node", "server.js"]
```

## Remediation steps
1. Change every relative `WORKDIR` value (e.g. `WORKDIR app`, `WORKDIR src/app`) to an absolute path (e.g. `WORKDIR /app`, `WORKDIR /src/app`).
2. If using a variable-based path (`WORKDIR $APP_HOME`), ensure that variable is itself defined as an absolute path via `ARG`/`ENV` earlier in the file.
3. Verify subsequent `COPY`/`ADD`/`RUN` instructions still function correctly after making the path absolute and explicit, since relative-path assumptions elsewhere in the file may have depended on the prior (implicit) working directory.
4. Re-run the scan against `src/cloud/frontend/self-serve-video/Dockerfile` to confirm it now passes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/WorkdirIsAbsolute.py
- Docker WORKDIR reference: https://docs.docker.com/reference/dockerfile/#workdir
