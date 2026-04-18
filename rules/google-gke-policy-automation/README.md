# google/gke-policy-automation

- Upstream: https://github.com/google/gke-policy-automation
- License: Apache-2.0 (preserved as `LICENSE` alongside these files)
- Commit SHA at import: `93c37540da40e16ef75dfa5b3d84af08a3e243ca`
- Imported files: 95 `.rego` files across `gke-policies/` (v1) and `gke-policies-v2/` (v2), tests removed

## What these rules cover

Google-curated GKE (Google Kubernetes Engine) best-practice policies, mapping to CIS GKE Benchmark and Google Cloud Security Command Center findings. Rule domains include:

- Control-plane hardening: private endpoint, authorized networks, IP allowlists, disabled client certificate auth, disabled basic auth, secure boot
- Workload identity, Shielded GKE Nodes, encryption at rest (CMEK / Kubernetes secrets)
- Binary Authorization enabled for image signing
- Release channels and maintenance windows configured
- Cluster autoscaler and Node auto-upgrade / auto-repair
- Logging and monitoring components enabled (control plane, workload, managed prometheus)
- Network policy, HTTP load balancer, gateway API configuration
- Node pool hardening: boot disk encryption, cos_containerd, integrity monitoring, no legacy metadata endpoints, minimum CPU platform
- Identity-Aware Proxy / IAM bindings for GKE service account

Two tracks are included:

- `gke-policies/` — v1 policies (older data model, GKE REST API shape).
- `gke-policies-v2/` — v2 policies (`package gke.policy.*`, `input.data.gke.*` shape). The `v2` set is the actively maintained one.

## Layout

```
google-gke-policy-automation/
├── gke-policies/           ← v1 rules
└── gke-policies-v2/
    └── policy/             ← v2 rules
```

## Input-schema compatibility

**These rules DO NOT run directly under Vulnetix.** The rules expect `input.data.gke.*` — a structured GKE cluster / node pool description fetched from the Google Cloud API by the `gke-policy` tool. Example:

```json
{
  "data": {
    "gke": {
      "binary_authorization": { "enabled": true },
      "master_authorized_networks_config": { ... },
      "node_pools": [ ... ]
    }
  }
}
```

The Vulnetix CLI passes `{ "file_contents": { ... } }`, so `input.data.gke` is `undefined` and `violation` yields nothing.

**To use them with Vulnetix you need one of:**

1. A Rego adapter that parses Terraform for `google_container_cluster` / `google_container_node_pool` resources from `input.file_contents`, derives a `data.gke` shape, then wraps the upstream `violation` into Vulnetix `findings`.
2. Run **gke-policy-automation** separately (`gke-policy check cluster --cluster ...`) and ingest its SARIF/JSON output.

Until an adapter is built, the rules are shipped here as a **policy archive / reference**. The `# METADATA` block on every rule carries CIS control mapping, severity, SCC category, and a recommendation — a useful compliance-mapping corpus.

## Using with the Vulnetix CLI

```bash
vulnetix scan --rule Vulnetix/community-rules --disable-default-rules --dry-run
```

## Attribution

Copyright 2022 Google LLC. Licensed under the Apache License, Version 2.0. See `LICENSE`.
