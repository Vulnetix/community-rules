# hojjatsajjadinia/OPA-Security-Rules (clean-room port)

- Upstream: https://github.com/hojjatsajjadinia/OPA-Security-Rules
- Commit SHA at import: `f14f237d90e7b1d896f1e172d512b7de95ae12df`

## What these rules cover

A compact Dockerfile hardening rule set for Conftest:

- Require a non-root, non-`USER` named user
- Forbid `--chown=root`/`--chown=0`/`--chown=toor` in `COPY` / `ADD`
- Require multi-stage build (`COPY --from=...`) where applicable
- Forbid exposing SSH (`22`) or RDP (`3389`)
- Deny secrets (`passwd`, `password`, `token`, `api_key`, ...) in `ENV`
- Prefer `COPY` over `ADD`
- Forbid the `:latest` tag on base images
- Forbid public multi-segment registry base images (require trusted registry)
- Forbid `curl` / `wget` in `RUN`
- Forbid `apt/yum/apk/dnf/pip upgrade|update`

## Layout

```
hojjatsajjadinia-opa-security-rules/
├── opa-docker-rules.rego
└── README.md
```

## Input-schema compatibility

**Ported** to the Vulnetix `input.file_contents` text-scanning shape. Each Dockerfile-like file is scanned line by line; the rule emits findings directly.

## Using with the Vulnetix CLI

```bash
# Loads and emits findings directly under the Vulnetix CLI.
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

Copyright (c) 2023 Hojat Sajadinia. Originally licensed under the MIT License.
