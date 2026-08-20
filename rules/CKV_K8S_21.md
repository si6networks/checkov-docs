# CKV_K8S_21: The default namespace should not be used
## Severity
**LOW** (score: 2.0/10)

Deploying into the default namespace is primarily an organizational hygiene issue that weakens RBAC/network-policy segmentation boundaries but does not itself constitute an exploitable vulnerability.

## Summary
This check fails any namespaced Kubernetes resource that either omits `metadata.namespace` or sets it to `default`, because relying on the `default` namespace mixes unrelated workloads together and undermines namespace-based isolation and RBAC scoping.

## Applicability
- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`, `Service`, `Secret`, `ServiceAccount`, `Role`, `RoleBinding`, `ConfigMap`, `Ingress`
- **Resource/entity types (Terraform):** the corresponding `kubernetes_*` resources (`kubernetes_pod`, `kubernetes_deployment`, `kubernetes_daemonset`, `kubernetes_stateful_set`, `kubernetes_replication_controller`, `kubernetes_job`, `kubernetes_cron_job`, `kubernetes_service`, `kubernetes_secret`, `kubernetes_service_account`, `kubernetes_role_binding`, `kubernetes_config_map`, `kubernetes_ingress`, and their `_v1` variants)

## Why it matters
The `default` namespace is created automatically in every cluster and, without deliberate governance, becomes a dumping ground where unrelated teams' workloads, Secrets, RBAC bindings, and ConfigMaps end up co-located. This defeats several security controls that depend on namespace boundaries: NetworkPolicies are typically scoped by namespace, RBAC Roles/RoleBindings are namespace-scoped, and resource quotas/limits are applied per namespace. Applications sharing the `default` namespace can often read each other's Secrets and ConfigMaps if RBAC is not unusually strict, and a compromise of one workload's ServiceAccount has a much larger blast radius when everything lives in one undifferentiated namespace. It also makes auditing, cost attribution, and incident response harder because there is no reliable way to scope "all resources belonging to application X" using namespace-based filtering.

## How Checkov evaluates this
- **Kubernetes-native (`DefaultNamespace`):** reads `metadata.namespace`. If present and not equal to `"default"`, PASSED (also PASSED if the `HELM_NAMESPACE` environment variable is set to something other than `default`, to support pre-render Helm chart validation). If `namespace` is missing entirely, or explicitly `"default"`, the result is FAILED — with two built-in exceptions: the `default` `ServiceAccount` object and the `kubernetes` `Service` object (both of which Kubernetes creates automatically in the `default` namespace and cannot be relocated) are always treated as PASSED.
- **Terraform (`DefaultNamespace`):** fails if `metadata` block is absent, or if `metadata[0].namespace == ["default"]`; passes only when a non-default namespace is explicitly set.

## Non-compliant example
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: recording-session-ranker
  # no namespace specified -> defaults to "default"
spec:
  template:
    spec:
      containers:
        - name: ranker
          image: myorg/ranker:1.0
      restartPolicy: Never
```

## Remediated example
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: recording-session-ranker
  namespace: cognition-yz
spec:
  template:
    spec:
      containers:
        - name: ranker
          image: myorg/ranker:1.0
      restartPolicy: Never
```

## Remediation steps
1. Create (or identify) an appropriately scoped namespace for each application/team (e.g. `cognition-yz`, `data-pipeline`) rather than relying on `default`.
2. Add an explicit `metadata.namespace` field to every affected manifest — for our repo, add it to `job.yaml`, `cronjob.yaml`, and `deployment.yaml` under `wild_west/cognition/yz/web_services/*`.
3. If manifests are applied via Kustomize, add a `namespace:` field at the kustomization root instead of editing every resource individually — this rewrites `metadata.namespace` for all resources in that overlay.
4. If deployed via Helm, ensure `--namespace` / `.Release.Namespace` is used consistently and templates do not hardcode or omit the namespace field.
5. Apply a `ResourceQuota` and `NetworkPolicy` per namespace, and scope RBAC RoleBindings to the new namespace, to realize the isolation benefits once workloads are moved out of `default`.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/DefaultNamespace.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/DefaultNamespace.py)
- [Kubernetes: Namespaces](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)
