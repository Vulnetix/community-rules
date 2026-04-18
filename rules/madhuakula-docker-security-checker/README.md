# madhuakula/docker-security-checker

- Upstream: https://github.com/madhuakula/docker-security-checker
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `5e6f4b370481d9ceb25a276763ad0dc5a8503b5e`
- Imported files: 1 `.rego` file (`security.rego`) from upstream `policy/`

## What these rules cover

Dockerfile hardening checks, intended for Conftest:

- Suspicious env / arg keys (`password`, `secret`, `api_key`, …) — potential credential leaks baked into image layers
- Package upgrades in the same `RUN` as `apt-get`/`apk` (leads to non-reproducible images)
- `:latest` (or `:LATEST`) image tags
- `ADD` used for local files (prefer `COPY`)
- `sudo` usage inside the image

All rules analyse a **single Dockerfile** parsed by Conftest into a list of `{Cmd, Value}` records.

## Layout

```
madhuakula-docker-security-checker/
├── security.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Operates on a **local Dockerfile** parsed by Conftest. Purely local; no API calls.

Under the Vulnetix CLI (`input.file_contents`), rules load but won't fire until an adapter Dockerfile-parses `input.file_contents["**/Dockerfile*"]` and rebinds `input` to the parsed instruction list.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Conftest:
conftest test --policy rules/madhuakula-docker-security-checker/ Dockerfile
```

## Attribution

Copyright Madhu Akula. Licensed under the MIT License. See `LICENSE`.
