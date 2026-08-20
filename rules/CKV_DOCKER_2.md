# CKV_DOCKER_2: Ensure that HEALTHCHECK instructions have been added to container images

## Severity
**LOW** (score: 2.0/10)

Missing HEALTHCHECK instructions mainly affect availability and incident detection (an unhealthy container keeps serving traffic undetected) rather than confidentiality or integrity.

## Summary
This check requires that a Dockerfile includes a `HEALTHCHECK` instruction so the container runtime can determine whether the running container is actually healthy, not merely alive.

## Applicability
Dockerfiles — this check applies to the Dockerfile as a whole (`supported_instructions = ("*",)`, i.e. it inspects the complete parsed instruction set) looking specifically for a `HEALTHCHECK` instruction anywhere in the file.

## Why it matters
Without a `HEALTHCHECK`, Docker (and orchestrators relying on the container's own health signal) only knows whether the container's main process is running — not whether the application inside is actually serving traffic correctly. A process can be alive but deadlocked, out of memory, unable to reach a dependency, or stuck in an initialization loop, and without a health check the container will appear "healthy" (running) indefinitely. This delays detection of outages, can leave broken instances receiving traffic behind a load balancer, and undermines automated recovery (e.g., `docker run --restart` policies or orchestrator liveness/readiness integration that key off the container's own signal) — a reliability and incident-response gap more than a direct exploit, but one that materially extends the blast radius and duration of an incident, including a security incident where an application starts misbehaving.

## How Checkov evaluates this
The check (`HealthcheckExists`) receives the fully parsed Dockerfile as a mapping of instruction name to the list of that instruction's occurrences. It iterates the instruction names present in the file; if `"HEALTHCHECK"` appears as a key, it PASSES (returning the healthcheck content as evaluated). If no `HEALTHCHECK` instruction exists anywhere in the file, it FAILS.

## Non-compliant example
```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

CMD ["python", "server.py"]
```

## Remediated example
```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/healthz || exit 1

CMD ["python", "server.py"]
```

## Remediation steps
1. Add a `HEALTHCHECK` instruction to the Dockerfile that exercises a real, lightweight endpoint or command reflecting actual application readiness (an HTTP health endpoint, a process/port check, a DB connectivity probe as appropriate).
2. Tune `--interval`, `--timeout`, `--start-period`, and `--retries` to match the application's real startup and response characteristics — an overly aggressive check can cause false "unhealthy" restarts.
3. Ensure the health-check command/tool (e.g., `curl`, `wget`) is actually present in the final image stage; if using a minimal/distroless base, use an in-process check binary instead of shelling out to a tool that isn't installed.
4. If the container is orchestrated by Kubernetes (which uses its own `livenessProbe`/`readinessProbe` rather than Docker's `HEALTHCHECK`), still add a `HEALTHCHECK` for consistency with plain `docker run` usage and local development, and mirror the same logic in the Kubernetes probes.
5. Re-run the scan against the listed example Dockerfiles to confirm each now passes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/HealthcheckExists.py
- Docker HEALTHCHECK reference: https://docs.docker.com/reference/dockerfile/#healthcheck
