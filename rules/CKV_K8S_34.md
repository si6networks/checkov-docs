# CKV_K8S_34: Ensure that Tiller (Helm v2) is not deployed

## Severity
**LOW** (score: 2.0/10)

Tiller ran as a highly privileged, unauthenticated-by-default in-cluster service that effectively granted cluster-admin to anyone who could reach it, making its mere presence a well-known path to full cluster compromise and remote code execution.

## Summary
This check flags workloads that deploy the Tiller component (Helm v2's server-side agent) based on its image name or characteristic labels.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **Kubernetes manifests**: container-level check across kinds `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`.
- **Terraform**: resource types `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`.

## Why it matters
Tiller, Helm v2's in-cluster server component, ran with broad (often `cluster-admin`-equivalent) privileges by default and exposed an unauthenticated gRPC endpoint inside the cluster network — any pod or user with network access to the Tiller service could use it to install, upgrade, or delete releases across the cluster without further authentication. This made Tiller a well-known lateral-movement and privilege-escalation vector: compromising any single pod on the pod network could be enough to pivot into full cluster control via Tiller. Helm v2 (and Tiller) has been end-of-life since Helm v3's release (which removed the server-side component entirely), so any Tiller instance found running today is also very likely unpatched. Checkov flags its presence as inherently insecure and obsolete.

## How Checkov evaluates this
The shared `Tiller.is_tiller()` logic (used by both the Kubernetes and Terraform checks) returns FAIL if either:
- The container's `image` field is a string containing the substring `tiller`, OR
- The resource's `metadata.labels` has `app == "helm"` or `name == "tiller"` (checked at the top-level metadata, and for Deployment-style resources also at `spec.template.metadata.labels`).
Otherwise it PASSES.

## Non-compliant example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tiller-deploy
  labels:
    app: helm
    name: tiller
spec:
  replicas: 1
  selector:
    matchLabels:
      app: helm
      name: tiller
  template:
    metadata:
      labels:
        app: helm
        name: tiller
    spec:
      containers:
        - name: tiller
          image: gcr.io/kubernetes-helm/tiller:v2.17.0
```

## Remediated example
```yaml
# Do not deploy Tiller / Helm v2 at all.
# Migrate to Helm v3, which has no in-cluster server-side component:
#   helm3 install myrelease ./mychart
# RBAC for chart installs is enforced via the client's own kubeconfig
# credentials and standard Kubernetes RBAC — no cluster-wide privileged
# agent required.
```

## Remediation steps
1. Delete any Tiller Deployment/Pod manifests and remove `helm2`/Tiller from CI/CD tooling.
2. Migrate all charts and release management to Helm v3 (`helm3`), which performs installs client-side using the invoking user's own kubeconfig and RBAC permissions.
3. Run `helm-2to3` (the official Helm migration plugin) to convert any existing Helm v2 release data/state before removing Tiller.
4. Audit RBAC bindings previously granted to the Tiller service account and remove them once Tiller is decommissioned, since they were often overly broad.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/Tiller.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/Tiller.py)
- [Helm docs: Migrate from Helm v2 to v3](https://helm.sh/docs/topics/v2_v3_migration/)
