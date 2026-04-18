# starkross/augur

- Upstream: https://github.com/starkross/augur
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `e7fe50af791fa75a8ee3faecf277f0097f679232`
- Imported files: `rules/` directory from upstream (tests stripped)

## What these rules cover

A static analysis ruleset for **OpenTelemetry Collector configuration files**. Rules examine local YAML collector configs and flag misconfigurations in:

- **Receivers** — insecure TLS / missing auth / unsupported ports
- **Processors** — missing `batch`, `memory_limiter`, wrong order, resource bottlenecks
- **Exporters** — plaintext endpoints, missing retry/queue/backoff, undeclared but-referenced exporters
- **Extensions** — unused / duplicated / missing `health_check` or `pprof`
- **Pipelines** — references to receivers/processors/exporters that are not defined; type mismatches
- **Service.telemetry** — missing logs, undesired verbosity
- **Reliability & security posture** — secret material in config values (should use `${env:...}`), missing auth

## Layout

```
starkross-augur/
└── rules/
    └── policy/
        ├── lib/
        │   └── helpers.rego
        └── main/
            ├── exporter.rego
            ├── extension.rego
            ├── lifecycle.rego
            ├── main.rego
            ├── memory.rego
            ├── pipeline.rego
            ├── receiver.rego
            ├── reliability.rego
            └── security.rego
```

## Input-schema compatibility

Operates on a **local OpenTelemetry Collector YAML config** parsed directly into `input` (top-level keys: `receivers`, `processors`, `exporters`, `service`, `extensions`). Purely local; no API calls.

Under the Vulnetix CLI (`input.file_contents`), the rules load but need an adapter to YAML-parse `input.file_contents[path]` (for `otelcol-*.yaml` and similar) and rebind the parsed object as `input`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via the upstream Augur CLI or OPA:
opa eval --input otelcol-config.yaml --data rules/starkross-augur/rules/ 'data.main.deny'
```

## Attribution

Copyright the Augur contributors. Licensed under the Apache License, Version 2.0. See `LICENSE`.
