# CKV_K8S_35: Prefer using secrets as files over secrets as environment variables

## Severity
**LOW** (score: 2.0/10)

Injecting secrets as environment variables increases the chance of accidental disclosure (via process listings, crash dumps, logging, or child-process inheritance) compared to file mounts, but does not by itself expose the secret to unauthorized parties.

## Summary
This check ensures containers do not inject Kubernetes `Secret` data via environment variables (`env[].valueFrom.secretKeyRef` or `envFrom[].secretRef`), preferring instead that secrets be mounted as files.

## Applicability
- **Kubernetes manifests**: container-level check across kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`.
- **Terraform**: resource types `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`, at `spec.container[].env[].value_from.secret_key_ref` and `spec.container[].env_from[].secret_ref`.

## Why it matters
Secrets exposed as environment variables are inherently more prone to leakage than secrets mounted as files: environment variables are trivially dumped by `/proc/<pid>/environ`, are frequently captured in crash reports, are inherited by every child process a container spawns (including any shell an attacker gets via RCE), and are commonly logged in full by error handlers, APM tools, or `env`/`printenv` debugging commands — often without anyone realizing secret material is being written to logs. File-mounted secrets, by contrast, live at a specific path, are not automatically inherited by child processes, are easier to restrict via filesystem permissions, and are far less likely to be accidentally captured by generic logging/monitoring instrumentation (CIS Benchmark 5.4.1). This is why the check flags any use of `secretKeyRef`/`secretRef` in env-based secret injection.

## How Checkov evaluates this
For each container, the check inspects `env[]` entries: if any entry's `valueFrom` contains `secretKeyRef`, the check FAILS. It also inspects `envFrom[]` entries: if any contains `secretRef`, the check FAILS. If neither pattern is present anywhere in the container (i.e., no secret is sourced via environment variables), it PASSES. Plain env vars with literal values, or `configMapKeyRef`, do not trigger this check.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cardio
spec:
  template:
    spec:
      containers:
        - name: app
          image: myrepo/cardio:2.1.0
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db-credentials
                  key: password
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cardio
spec:
  template:
    spec:
      containers:
        - name: app
          image: myrepo/cardio:2.1.0
          volumeMounts:
            - name: db-creds
              mountPath: /etc/secrets/db
              readOnly: true
      volumes:
        - name: db-creds
          secret:
            secretName: db-credentials    # mounted as file instead of env var
```

## Remediation steps
1. Replace `env[].valueFrom.secretKeyRef` / `envFrom[].secretRef` with a `secret` volume mounted into the container's filesystem, then have the application read the secret from the mounted file path.
2. If the application can't be changed to read from a file, use an init-container or sidecar that reads the mounted secret file and writes it only into an in-memory location the main process reads once at startup (avoid re-exporting it back into the environment).
3. For the flagged files in this repo (`pmx/cloud/openstreetmap/k8s.yml`, the Argo DB migration job, and `magna_k8s/k8s.yml`), convert the `env`/`envFrom` secret references to `volumeMounts` + `volumes.secret`.
4. Set restrictive file permissions (`defaultMode`) on the secret volume and ensure the container runs as non-root so only the intended process can read it.
5. Audit logging/APM configuration to confirm environment variables aren't being globally dumped into logs, as a defense-in-depth measure for any secrets that remain env-based during migration.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/Secrets.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/Secrets.py)
- [Kubernetes docs: Distribute Credentials Securely Using Secrets](https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/)
