# CKV_K8S_22: Use read-only filesystem for containers where possible
## Severity
**LOW** (score: 2.0/10)

A writable root filesystem does not itself grant access but increases the blast radius of any successful RCE by letting an attacker persist tools or tamper with the container's own binaries.

## Summary
This check fails any container whose `securityContext.readOnlyRootFilesystem` is not explicitly set to `true`, because a writable root filesystem lets an attacker who gains code execution persist changes, drop tools, or tamper with the running application inside the container.

## Applicability
- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `PodTemplate`, `Deployment`, `DeploymentConfig`, `ReplicaSet`, `ReplicationController`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
By default a container's root filesystem is writable, meaning any process running inside it — including a compromised application process — can write arbitrary files anywhere in the container's filesystem: modify or replace application binaries, drop and execute additional malware/tools, tamper with configuration to weaken further defenses, or attempt to write to mounted paths in ways that could affect the host or other containers if volumes are shared. Enforcing `readOnlyRootFilesystem: true` closes off this entire class of runtime tampering — an attacker with code execution can no longer persist a foothold in the container's own filesystem, drop additional payloads to disk, or overwrite the application itself, forcing them into strictly memory-resident techniques which are considerably harder to sustain and detect less. It is one of the most impactful and broadly applicable container hardening controls and is a baseline recommendation from CIS, NSA/CISA Kubernetes Hardening Guidance, and the Pod Security Standards.

## How Checkov evaluates this
- **Kubernetes-native (`ReadOnlyFilesystem`):** for each container, checks `securityContext.readOnlyRootFilesystem`. If truthy, PASSED. Otherwise (absent, `false`, or no `securityContext` block) FAILED.
- **Terraform (`ReadonlyRootFilesystem`):** inspects `spec[0].container[*].security_context[0].read_only_root_filesystem` (following `template[0].spec[0]` for Deployments). Fails unless the value is exactly `[True]`.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dashboard
spec:
  template:
    spec:
      containers:
        - name: dash
          image: myorg/dashboard:1.0
          securityContext: {}   # readOnlyRootFilesystem not set -> writable by default
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dashboard
spec:
  template:
    spec:
      containers:
        - name: dash
          image: myorg/dashboard:1.0
          securityContext:
            readOnlyRootFilesystem: true
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
```

## Remediation steps
1. Add `securityContext.readOnlyRootFilesystem: true` to each container in the affected Deployments (`observability`, `dash`, `argo` bases/overlays under `pmx/cloud/simulations/k8s-manifests/`), via a Kustomize patch if managed through `kustomization.yaml`.
2. Identify any paths the application legitimately writes to at runtime (temp files, caches, sockets, PID files) and mount `emptyDir` (or a dedicated PVC) volumes at those specific paths so the app keeps working with a read-only root.
3. Test thoroughly in a non-production environment first — many images (especially those using package managers, writing logs to arbitrary paths, or unpacking to `/tmp`) will fail to start until writable mount points are added.
4. Where the check header says "where possible," treat that as guidance to fix the underlying image/app to avoid unnecessary writes rather than leaving the root filesystem writable as a workaround.
5. Enforce via Pod Security Admission or an admission controller so this becomes a hard requirement for new workloads going forward.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ReadOnlyFilesystem.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ReadonlyRootFilesystem.py)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
