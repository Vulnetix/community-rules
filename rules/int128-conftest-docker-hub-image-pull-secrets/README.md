# int128/conftest-docker-hub-image-pull-secrets

- Upstream: https://github.com/int128/conftest-docker-hub-image-pull-secrets
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `d583284a05248e5f7d4417cea5caefe8dbd5e502`
- Imported files: 1 `.rego` (`deny.rego`)

## What these rules cover

A focused Conftest policy that enforces correct `imagePullSecrets` usage for Docker Hub images on Kubernetes workloads:

- **Deny** workloads referencing Docker Hub images (e.g., `nginx:1.25`, `library/alpine`, `myuser/myapp:v1`) that lack an `imagePullSecrets` entry — Docker Hub rate-limiting makes anonymous pulls unreliable in CI/production.
- **Deny** workloads with `imagePullSecrets` set when only non-Docker-Hub images (e.g., `ghcr.io/...`, `gcr.io/...`) are used — the secret is then unnecessary.

Applies to `Deployment`, `Job`, `StatefulSet`, `DaemonSet`.

## Layout

```
int128-conftest-docker-hub-image-pull-secrets/
├── deny.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Standard conftest shape — a parsed Kubernetes YAML manifest as `input`:

```rego
input.kind                                         # Deployment, Job, StatefulSet, DaemonSet
input.metadata.name
input.spec.template.spec.containers[_].image
input.spec.template.spec.imagePullSecrets[_]
```

Purely local: no cluster calls, no network.

Under Vulnetix CLI (`input.file_contents`), the rule loads but needs an adapter that parses each `*.yaml` manifest and evaluates against it.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter required to feed parsed K8s YAML as input.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via conftest (upstream):
conftest test --policy rules/int128-conftest-docker-hub-image-pull-secrets ./manifests
```

## Attribution

Copyright int128. Licensed under the Apache License, Version 2.0. See `LICENSE`.
