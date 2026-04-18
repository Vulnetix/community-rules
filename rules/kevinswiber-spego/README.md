# kevinswiber/spego

- Upstream: https://github.com/kevinswiber/spego
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `5d9c41a4d3eb1d988a880377d7963cd09eb05f62`
- Imported files: 24 ported rules + 1 shared helper (upstream `src/` tree dropped)

## What these rules cover

A port of common **OpenAPI Specification (OAS) 3.x linting rules** to Rego
under the Vulnetix input shape — originally modelled after the Spectral
ruleset. Each rule walks every OpenAPI document found in
`input.file_contents` and emits Vulnetix findings.

| Rule ID | Spectral name | Purpose |
|---|---|---|
| SPEGO-OAS-0001 | `info-contact` | `info.contact` must exist |
| SPEGO-OAS-0002 | `info-description` | `info.description` must be non-empty |
| SPEGO-OAS-0003 | `info-license` | `info.license` must exist |
| SPEGO-OAS-0004 | `license-url` | `info.license.url` must be non-empty |
| SPEGO-OAS-0005 | `contact-properties` | contact must include name/url/email |
| SPEGO-OAS-0006 | `openapi-tags` | `tags` array must be non-empty |
| SPEGO-OAS-0007 | `openapi-tags-uniqueness` | tag names must be unique |
| SPEGO-OAS-0008 | `tag-description` | each tag needs a description |
| SPEGO-OAS-0009 | `operation-description` | each op needs description |
| SPEGO-OAS-0010 | `operation-operationId` | each op needs operationId |
| SPEGO-OAS-0011 | `operation-operationId-unique` | operationIds unique in doc |
| SPEGO-OAS-0012 | `operation-operationId-valid-in-url` | URL-safe operationIds |
| SPEGO-OAS-0013 | `operation-parameters` | parameter uniqueness + body/formData rules |
| SPEGO-OAS-0014 | `operation-singular-tag` | at most one tag per op |
| SPEGO-OAS-0015 | `operation-success-response` | each op needs a 2xx/3xx response |
| SPEGO-OAS-0016 | `operation-tag-defined` | op tags declared in global `tags` |
| SPEGO-OAS-0017 | `operation-tags` | each op needs tags |
| SPEGO-OAS-0018 | `path-declarations-must-exist` | no `{}` in path templates |
| SPEGO-OAS-0019 | `path-keys-no-trailing-slash` | no trailing slash on paths |
| SPEGO-OAS-0020 | `path-not-include-query` | no query string in path keys |
| SPEGO-OAS-0021 | `path-params` | templated vars must be declared + unique |
| SPEGO-OAS-0022 | `no-eval-in-markdown` | no `eval(` in title/description |
| SPEGO-OAS-0023 | `no-script-tags-in-markdown` | no `<script` in title/description |
| SPEGO-OAS-0024 | `duplicated-entry-in-enum` | enum values unique |

## Layout

```
kevinswiber-spego/
├── _lib/openapi.rego          (vulnetix.spego.openapi helper)
├── policies/
│   └── <rule-name>/<rule-name>.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

**Ported** to the Vulnetix `input.file_contents` input shape. The shared
helper `vulnetix.spego.openapi` detects OpenAPI/Swagger files by extension
(`.yaml`, `.yml`, `.json`), parses them with `yaml.unmarshal` /
`json.unmarshal`, and exposes the parsed docs via `openapi.specs`. Each
rule iterates over `openapi.specs` and applies the equivalent Spectral
check.

Notes on the port vs. upstream:
- The upstream `path-params` rule detects path-template collisions via
  normalised path comparison; that portion is dropped. The port keeps the
  three tractable sub-checks: duplicate names in a single template,
  duplicate definitions, and undefined templated vars.
- `operation-operationId-unique` scope remains single-document (upstream
  behaviour).
- The helper accepts any JSON/YAML file as a candidate but only emits
  findings when the parsed object carries `openapi` or `swagger` keys.

## Using with the Vulnetix CLI

```bash
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

Copyright Kevin Swiber. Licensed under the Apache License, Version 2.0. See `LICENSE`.
