# dstrebel/validate-k8s-apis

- Upstream: https://github.com/dstrebel/validate-k8s-apis
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `ea7b4f2982e99cc31287bd267a6bb1695084cfa9`
- Imported files: `policy/base.rego`

## What these rules cover

A compact Rego rule set for **Kubernetes manifest YAML** that denies use of deprecated API versions across Kubernetes 1.16–1.22:

- `apps/v1beta1`, `apps/v1beta2` → use `apps/v1`
- `extensions/v1beta1` DaemonSet / Deployment / ReplicaSet → `apps/v1`
- `extensions/v1beta1` NetworkPolicy → `networking.k8s.io/v1`
- `extensions/v1beta1` PodSecurityPolicy → `policy/v1beta1`
- `extensions/v1beta1` Ingress → `networking.k8s.io/v1`
- Pre-1.22 CRD/Webhook/TokenReview/etc. `v1beta1` → `v1`

Handles both top-level resources and `v1/List`-wrapped multi-doc inputs.

## Layout

```
dstrebel-validate-k8s-apis/
├── base.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Operates on a **parsed Kubernetes manifest** at `input` (Conftest reads each local `.yaml` document and binds it). Purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to YAML-parse each manifest from `input.file_contents[path]` and rebind `input` to the parsed document.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Conftest (upstream path):
conftest test --policy rules/dstrebel-validate-k8s-apis/ deployment.yaml
```

## Attribution

Copyright the dstrebel/validate-k8s-apis contributors. Licensed under the MIT License. See `LICENSE`.
