# CKV_K8S_159: Limit the use of git-sync to prevent code injection
## Severity
**HIGH** (score: 7.5/10)

Uncontrolled git-sync sidecars pull and can execute code from a remote git source at runtime, so a compromised or unauthenticated repo/branch reference creates a direct code-injection/RCE path into the cluster.

## Summary
This check flags any Pod/workload container that sets the environment variable `GITSYNC_GIT`, because that variable is used by the `git-sync` sidecar to pass raw arguments to the underlying `git` binary and has a documented command-injection vulnerability.

## Applicability
- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `PodTemplate`, `Deployment`, `DeploymentConfig`, `ReplicaSet`, `ReplicationController`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
`git-sync` is a widely used sidecar/init container that periodically pulls a Git repository into a shared volume (common for GitOps config sync, Airflow DAG syncing, etc.). Security research published by Akamai in August 2024 documented that certain `git-sync` configuration inputs — notably ones reachable via the `GITSYNC_GIT` environment variable — can be manipulated to inject arbitrary arguments into the `git` command line invoked by the sidecar, leading to command injection inside the container. Because `git-sync` containers frequently run with access to shared volumes, service account tokens, or in privileged sync loops, a successful injection can lead to arbitrary code execution in the pod, exfiltration of mounted secrets, or lateral movement across the cluster. Any manifest that explicitly sets this variable (rather than relying on safer, structured configuration flags) is treated as exposing this attack surface.

## How Checkov evaluates this
Two implementations exist:
- **Kubernetes-native (`DangerousGitSync`, `BaseK8sContainerCheck`):** iterates over each container's `env` list. If any entry has `name == "GITSYNC_GIT"`, the check returns FAILED. Otherwise PASSED.
- **Terraform (`kubernetes_pod`/`kubernetes_deployment` resources):** walks `spec[0].container[*].env[*]` (following `spec.template.spec` for Deployments) and fails if any `env` block's `name` equals `["GITSYNC_GIT"]`.

Note the Terraform implementation's comparison `env.get("name") == ["GITSYNC_GIT"]` reflects Terraform's list-wrapped HCL attribute representation internally, not a literal list value in the HCL you write.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dag-sync
spec:
  template:
    spec:
      containers:
        - name: git-sync
          image: registry.k8s.io/git-sync/git-sync:v4.2.1
          env:
            - name: GITSYNC_GIT
              value: "--upload-pack=/bin/sh -c 'id>/tmp/x'"
```

## Remediated example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dag-sync
spec:
  template:
    spec:
      containers:
        - name: git-sync
          image: registry.k8s.io/git-sync/git-sync:v4.6.2  # patched version
          env:
            - name: GITSYNC_REPO
              value: "https://github.com/example/dags.git"
            - name: GITSYNC_REF
              value: "main"
          # GITSYNC_GIT removed entirely — use dedicated, non-passthrough env vars
```

## Remediation steps
1. Remove any `GITSYNC_GIT` environment variable from git-sync containers; use the dedicated, well-typed variables (`GITSYNC_REPO`, `GITSYNC_REF`, `GITSYNC_DEPTH`, etc.) instead of passing raw git arguments.
2. Upgrade `git-sync` to the latest patched image version that addresses the Akamai-reported command-injection issue.
3. If custom git invocation flags are unavoidable, validate/allow-list the values at admission time (e.g. via an OPA/Kyverno policy) rather than accepting arbitrary strings from a values file or Helm chart parameter.
4. Ensure the git-sync sidecar runs with a minimal service account and no more volume/secret access than required, so injection impact is contained even if it recurs.
5. Review upstream `git-sync` release notes (https://github.com/kubernetes/git-sync) for the specific CVE/security advisory reference before deploying.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/DangerousGitSync.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/DangerousGitSync.py)
- [Akamai: 2024 August Kubernetes git-sync Command Injection](https://www.akamai.com/blog/security-research/2024-august-kubernetes-gitsync-command-injection-defcon)
