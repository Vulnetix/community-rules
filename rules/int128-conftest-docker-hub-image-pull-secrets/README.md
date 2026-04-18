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

**Ported** from the Conftest-parsed-YAML shape to the Vulnetix `input.file_contents` text-scanning shape. The adapted rule splits each YAML file on `---` separators and inspects each document for `kind:`, `imagePullSecrets:`, and `image:` fields via regex.

## Using with the Vulnetix CLI

```bash
# Loads and emits findings directly under the Vulnetix CLI.
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

Copyright int128. Licensed under the Apache License, Version 2.0. See `LICENSE`.
