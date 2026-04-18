# boostsecurityio/poutine

- Upstream: https://github.com/boostsecurityio/poutine
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `c89412a84a4683a307a57a5425d04a6a071d278b`
- Imported files: 26 `.rego` files from `opa/rego/` (tests stripped)

## What these rules cover

Poutine is BoostSecurity's **supply-chain vulnerability scanner for CI/CD build pipelines**. Rego rules detect unsafe patterns in GitHub Actions workflows, GitLab CI configs, and Azure Pipelines:

| Rule | What it catches |
|---|---|
| `confused_deputy_auto_merge` | Auto-merge workflows that can be hijacked by untrusted PRs |
| `debug_enabled` | `ACTIONS_STEP_DEBUG`, `CI_DEBUG_TRACE`, `system.debug` left on — leaks secrets |
| `default_permissions_on_risky_events` | Risky event triggers with default (overly broad) `GITHUB_TOKEN` perms |
| `github_action_from_unverified_creator_used` | Third-party actions from non-verified publishers |
| `if_always_true` | Conditional expressions that always evaluate to true (guard bypass) |
| `injection` | Script injection in `${{ github.event.* }}` / `$CI_*` / Azure expressions |
| `job_all_secrets` | Jobs granted access to the entire org/repo secret namespace |
| `known_vulnerability_in_build_component` | CI component pinned to a GHSA-vulnerable version (OSV table in `external/osv.rego`) |
| `known_vulnerability_in_build_platform` | Build platform with known CVE |
| `pr_runs_on_self_hosted` | PR-triggered workflow running on a self-hosted runner (supply-chain risk) |
| `unpinnable_action` | Action that cannot be SHA-pinned |
| `untrusted_checkout_exec` | `pull_request_target` pattern that checks out and executes untrusted code |
| `unverified_script_exec` | `curl | sh` / unverified installer scripts in pipeline steps |

Supporting modules:

- `poutine.rego`, `poutine/utils.rego`, `poutine/config.rego` — rule framework, findings aggregation, package/config selection helpers
- `poutine/inventory/{github_actions,gitlab,azure_pipelines}.rego` — inventory queries used by the rules
- `poutine/queries/` — shared query helpers (`findings`, `format`, `inventory`)
- `poutine/format/json.rego` — JSON output formatting
- `external/osv.rego` — **static** OSV advisory table (GitHub Actions GHSAs baked into the policy)
- `external/build_platform.rego`, `external/reputation.rego` — static data tables for platform CVEs and publisher reputation

## Layout

```
boostsecurityio-poutine/
└── opa/
    └── rego/
        ├── poutine.rego
        ├── poutine/
        │   ├── config.rego, utils.rego
        │   ├── inventory/   (github_actions, gitlab, azure_pipelines)
        │   ├── queries/     (findings, format, inventory)
        │   └── format/json.rego
        ├── rules/           (13 finding-producing rules)
        └── external/        (static OSV + build_platform + reputation tables)
├── LICENSE
└── README.md
```

## Input-schema compatibility

Rules read from `input.packages[_]`, where each package has pre-parsed
`github_actions_workflows`, `gitlabci_configs`, and `azure_pipelines` fields.
The upstream `poutine` Go scanner produces this input shape by parsing
**local `.github/workflows/*.yml`, `.gitlab-ci.yml`, and `azure-pipelines.yml`
files**.

No HTTP fetches at eval time — the OSV advisory list is a static data table
baked into `external/osv.rego`.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that
parses each workflow YAML into poutine's `packages[_]` shape.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter needed to project workflow YAML into poutine packages shape.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via the upstream poutine CLI:
poutine analyze_local .
```

## Attribution

Copyright BoostSecurity.io and the poutine contributors. Licensed under the
Apache License, Version 2.0. See `LICENSE`.
