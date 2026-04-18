# fluxcd/multi-tenancy

- Upstream: https://github.com/fluxcd/multi-tenancy
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `2a5c9dae9eb97f5681da4d29f80bea1ceb00ea4c`
- Imported files: 2 `.rego` files from `.github/policy/`

## What these rules cover

A small conftest policy set that was applied to the FluxCD multi-tenancy
example repository's Kubernetes manifests as part of its CI pipeline. Two files:

- `kubernetes.rego` — shared helpers (`containers`, `is_service`, `is_deployment`, `is_pod`, `split_image`).
- `rules.rego` — the actual rule pack:
  - **Deny** images tagged `latest`
  - **Deny** Services without an `app` label selector
  - **Deny** Deployments without an `app` label selector in `spec.selector.matchLabels`
  - **Warn** on Deployments missing the `prometheus.io/scrape` + `prometheus.io/port` pod annotations

Rules use the conftest `deny[msg]` / `warn[msg]` convention.

## Layout

```
fluxcd-multi-tenancy/
├── kubernetes.rego
├── rules.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Rules expect a **single parsed Kubernetes YAML document as `input`** — the
standard conftest/OPA shape:

```rego
input.kind           # e.g. "Deployment", "Service"
input.metadata.name
input.spec.selector.matchLabels.app
input.spec.template.spec.containers[].image
```

Purely local: no cluster API calls, no HTTP fetches from rule code.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that
parses each `*.yaml` manifest and feeds it as the rule's `input`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter required to project each K8s YAML as input.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via conftest (as used upstream):
conftest test --policy rules/fluxcd-multi-tenancy ./manifests
```

## Attribution

Copyright 2020 The FluxCD Authors. Licensed under the Apache License,
Version 2.0. See `LICENSE`.
