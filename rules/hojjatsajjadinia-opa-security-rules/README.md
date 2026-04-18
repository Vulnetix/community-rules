# hojjatsajjadinia/OPA-Security-Rules

- Upstream: https://github.com/hojjatsajjadinia/OPA-Security-Rules
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `f14f237d90e7b1d896f1e172d512b7de95ae12df`
- Imported files: 1 `.rego` file (`opa-docker-rules.rego`)

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
├── LICENSE
└── README.md
```

## Input-schema compatibility

Operates on a **Conftest-parsed Dockerfile** — `input[i]` is a list of `{Cmd, Value, Flags, ...}` instruction objects. Purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to tokenize each Dockerfile from `input.file_contents[path]` into the `{Cmd, Value}` list shape and rebind `input`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Conftest (upstream path):
conftest test --policy rules/hojjatsajjadinia-opa-security-rules/ Dockerfile
```

## Attribution

Copyright (c) 2023 Hojat Sajadinia. Licensed under the MIT License. See `LICENSE`.
