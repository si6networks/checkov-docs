# CKV_GCP_99: Ensure that Pub/Sub Topics are not anonymously or publicly accessible
## Severity
**HIGH** (score: 7.5/10)

Granting `allUsers`/`allAuthenticatedUsers` on a Pub/Sub topic IAM binding exposes an internet-reachable entry point that can allow message injection/spoofing into backend pipelines or unauthorized read of topic metadata, though it stops short of direct host or data-store compromise.

## Summary
This check fails when a Google Cloud Pub/Sub topic's IAM policy grants access to `allUsers` or `allAuthenticatedUsers`, which would let anyone on the internet (or any Google account holder) publish to or manage the topic.

## Applicability
- **Framework:** Terraform
- **Resource types:** `google_pubsub_topic_iam_member`, `google_pubsub_topic_iam_binding`

The check runs on any Terraform resource block of these two types, regardless of which IAM role is granted.

## Why it matters
Pub/Sub topics are frequently used as ingestion points for event pipelines, logging, and inter-service messaging. If the topic's IAM binding grants a role (e.g., `roles/pubsub.publisher`, `roles/pubsub.editor`, or even `roles/pubsub.viewer`) to the special members `allUsers` or `allAuthenticatedUsers`, anyone — including unauthenticated internet clients (`allUsers`) or any user with a Google account anywhere in the world (`allAuthenticatedUsers`) — can interact with that topic. Depending on the role, this can allow:
- **Message injection/spoofing:** an attacker publishes forged or malicious messages that downstream subscribers process as trusted input, potentially triggering unintended business logic, log poisoning, or injection attacks in consuming services.
- **Denial of service / cost abuse:** flooding the topic with junk messages inflates Pub/Sub billing and can overwhelm downstream consumers.
- **Information disclosure:** if the role includes read/view permissions, an external party could inspect topic configuration, subscriptions, or (via associated permissions) message contents.

Because Pub/Sub is often wired directly into Cloud Functions, Dataflow, or other automated processing, a publicly writable topic effectively becomes an unauthenticated entry point into your backend systems.

## How Checkov evaluates this
The check (`PubSubPrivateTopic`) inspects the Terraform resource configuration differently depending on entity type:
- For `google_pubsub_topic_iam_member`: it reads the `member` attribute (a single principal string). If that value is `allUsers` or `allAuthenticatedUsers`, the check **FAILS**; any other principal **PASSES**.
- For `google_pubsub_topic_iam_binding`: it reads the `members` attribute (a list of principals). If **any** entry in that list is `allUsers` or `allAuthenticatedUsers`, the check **FAILS**; otherwise it **PASSES**.

If neither `member` nor `members` is present in the configuration, the function implicitly returns `None`, which Checkov treats as an unknown/skipped result rather than a definitive pass or fail.

## Non-compliant example
```hcl
resource "google_pubsub_topic" "events" {
  name = "app-events"
}

resource "google_pubsub_topic_iam_member" "public_publisher" {
  topic  = google_pubsub_topic.events.name
  role   = "roles/pubsub.publisher"
  member = "allUsers"
}

resource "google_pubsub_topic_iam_binding" "public_binding" {
  topic = google_pubsub_topic.events.name
  role  = "roles/pubsub.viewer"
  members = [
    "allAuthenticatedUsers",
    "serviceAccount:trusted-app@my-project.iam.gserviceaccount.com",
  ]
}
```

## Remediated example
```hcl
resource "google_pubsub_topic" "events" {
  name = "app-events"
}

resource "google_pubsub_topic_iam_member" "scoped_publisher" {
  topic  = google_pubsub_topic.events.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:ingest-svc@my-project.iam.gserviceaccount.com"
}

resource "google_pubsub_topic_iam_binding" "scoped_binding" {
  topic = google_pubsub_topic.events.name
  role  = "roles/pubsub.viewer"
  members = [
    "serviceAccount:trusted-app@my-project.iam.gserviceaccount.com",
  ]
}
```

## Remediation steps
1. Search your Terraform for `google_pubsub_topic_iam_member` and `google_pubsub_topic_iam_binding` resources.
2. Replace any `allUsers` or `allAuthenticatedUsers` principal with explicit `user:`, `serviceAccount:`, or `group:` members that actually need access.
3. Apply least privilege: grant only the specific role needed (e.g., `roles/pubsub.publisher` for a producer, not `roles/pubsub.editor`).
4. If public/anonymous publish is genuinely required (e.g., a public webhook receiver), front the topic with an authenticated proxy (such as a Cloud Function or API Gateway with its own auth) instead of granting IAM access directly to `allUsers`.
5. If your organization has an Org Policy constraint for domain-restricted sharing (`constraints/iam.allowedPolicyMemberDomains`), consider enabling it as defense-in-depth so public bindings are rejected at the platform level even if IaC review is bypassed.
6. Re-run `checkov` to confirm the resource now passes.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/PubSubPrivateTopic.py
- Google Cloud IAM documentation on predefined members: https://cloud.google.com/iam/docs/overview#cloud-iam-policy
