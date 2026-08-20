# CKV_K8S_30: Apply security context to your pods and containers

## Severity
**LOW** (score: 2.0/10)

Omitting an explicit securityContext leaves a container on its runtime's permissive defaults (e.g. root user, no capability drops), raising the blast radius of a container compromise even though it is not itself an exploitable misconfiguration.

## Summary
This check ensures that pods/containers (in Pod, Deployment, and related workload manifests) define a `securityContext` block rather than relying entirely on defaults.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes manifests**: kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet` — evaluated at the container level.
- **Terraform**: resource types `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`, at the `spec.container[].security_context` attribute.

## Why it matters
Without an explicit `securityContext`, containers run with unrestricted Kubernetes defaults: no drop of Linux capabilities, no `readOnlyRootFilesystem` enforcement, no `runAsNonRoot`, no explicit UID/GID, and `allowPrivilegeEscalation` left permissive. A `securityContext` is the primary Kubernetes mechanism to constrain what a container process (and any process an attacker spawns inside it via a code-execution vulnerability) can do to the host and other containers — e.g. writing to the root filesystem, escalating to root, retaining unnecessary Linux capabilities, or accessing host resources. Omitting it entirely is a strong signal that no hardening has been considered for the workload, leaving the container's blast radius at its maximum in the event of compromise.

## How Checkov evaluates this
- **Kubernetes check** (`ContainerSecurityContext`, a `BaseK8sContainerCheck`): for every container in the manifest, it checks whether `container.securityContext` is present and truthy. If present, PASS; if absent/empty, FAIL.
- **Terraform check**: walks into `spec` (following through `template.spec` for Deployment-style resources) to find `container` blocks; for each container, if `security_context` is not set, it FAILS immediately (first missing container fails the whole resource).

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: myrepo/web:1.4.0
          ports:
            - containerPort: 8080
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: app
          image: myrepo/web:1.4.0
          ports:
            - containerPort: 8080
          securityContext:                 # added
            runAsNonRoot: true
            runAsUser: 10001
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

## Remediation steps
1. Add a `securityContext` block at the container level (Checkov requires it at container scope even if pod-level context also exists).
2. At minimum, set `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, and `capabilities.drop: ["ALL"]`.
3. Add `readOnlyRootFilesystem: true` where the app doesn't need to write to its own filesystem; mount an `emptyDir` for any required scratch paths.
4. For the affected resources in this repo (`observability`, `dash`, `argo` kustomizations), edit the base Deployment manifests referenced by `kustomization.yaml` to add the container `securityContext`, then re-run Checkov to confirm the fix propagates through the overlays.
5. Consider setting a cluster-wide Pod Security Admission `baseline`/`restricted` policy as a backstop so future workloads can't regress to no security context.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ContainerSecurityContext.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/ContainerSecurityContext.py)
- [Kubernetes docs: Configure a Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
