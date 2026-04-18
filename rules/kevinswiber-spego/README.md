# kevinswiber/spego

- Upstream: https://github.com/kevinswiber/spego
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `5d9c41a4d3eb1d988a880377d7963cd09eb05f62`
- Imported files: 36 `.rego` files from upstream `src/` (tests stripped)

## What these rules cover

A port of common **OpenAPI Specification (OAS) 3.x linting rules** to Rego — modelled after the Spectral ruleset. Each rule carries a `# METADATA` block with `title`, `description`, and `severity` defaults, and every rule lives under `src/openapi/policies/<rule-name>/`. Highlights:

- `info-contact`, `info-description`, `info-license`, `license-url`, `contact-properties`
- `openapi-tags`, `openapi-tags-uniqueness`, `tag-description`
- `operation-description`, `operation-operationId` (+ `-unique`, `-valid-in-url`)
- `operation-parameters`, `operation-singular-tag`, `operation-success-response`
- `operation-tag-defined`, `operation-tags`, `path-declarations-must-exist`
- `path-keys-no-trailing-slash`, `path-not-include-query`, `path-params`
- `no-eval-in-markdown`, `no-script-tags-in-markdown`, `duplicated-entry-in-enum`

The `openapi.main` package aggregates results and exposes `problems`, `successes`, and `results` for downstream consumption.

## Layout

```
kevinswiber-spego/
└── src/
    └── openapi/
        ├── lib/lib.rego
        ├── main/      ← aggregator (problems/successes/results)
        └── policies/
            └── <rule-name>/<rule-name>.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Operates on a **parsed OpenAPI 3.x document** bound to `input` (JSON or YAML parsed to JSON). Purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to parse each OpenAPI doc from `input.file_contents[path]` and rebind `input` to the parsed document before collecting `data.openapi.main.problems`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via OPA against a local OpenAPI file:
opa eval --input openapi.json \
         --data rules/kevinswiber-spego/src/ \
         'data.openapi.main.problems'
```

## Attribution

Copyright Kevin Swiber. Licensed under the Apache License, Version 2.0. See `LICENSE`.
