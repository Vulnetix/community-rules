# spacelift-io/spacelift-policies-example-library (plan subset)

- Upstream: https://github.com/spacelift-io/spacelift-policies-example-library
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `c77a473d96cce714e55fbd12e4abc6f20c6c5f43`
- Imported files: 27 `.rego` files from `examples/plan/` only (tests stripped)

## What these rules cover

Spacelift publishes multiple policy kinds (`access`, `approval`, `login`,
`notification`, `plan`, `push`, `trigger`). Only the **`plan`** kind analyzes
Terraform plan JSON — everything else consumes runtime Spacelift events
(user logins, stack lifecycle, Slack/Discord notifications, etc.). This import
therefore includes **only the `plan` subset**; the other subdirs are excluded
per the offline-file-only policy.

The 27 imported `plan` policies cover:

| Policy | What it enforces |
|---|---|
| check-blast-radius | Fails PRs whose aggregated resource-change "blast radius" exceeds 100 |
| check-sanitized-value | Detects unsanitized secrets flowing through plan |
| deny-proposed-runs-warn-track-runs | Deny on PR, warn on tracked branch |
| do-not-delete-stateful-resources | Block deletion of stateful resources (RDS, S3, etc.) |
| dont-allow-resource-type | Deny an allow-list of resource types |
| enforce-cloud-provider | Restrict which cloud provider may be used |
| enforce-instance-type-list | Allow only specific EC2/GCE instance types |
| enforce-module-use-policy | Require a specific Terraform module source |
| enforce-password-length | Minimum password length on resources |
| enforce-sqlinstance-network | Cloud SQL must be on specific network |
| enforce-tags-on-resources | Mandatory tags on all resources |
| enforce-terraform-version-list | Restrict allowed Terraform versions |
| ensure-resource-creation-before-deletion | Ordering guarantees on replace |
| mandatory-and-acceptable-labels-{gcp,stack} | Label policies for GCP/stack |
| require-human-review-for-* | Drift-reconciliation, unreachable-hosts, update-deletion gates |
| require-reasonable-commit-size | Limit number of files per commit |
| trusted-engineers-bypass-review | Named engineers bypass review |
| warn-on-change-sensitive-resources | Warn when touching sensitive resources |
| **Scanner integrations** | `checkov-failed-checks`, `kics-severity-counter`, `terrascan-violated-policies`, `tfsec-high-severity-issues`, `trivy-high-severity-issues`, `infracost-monthly-cost-restriction` — treat scanner output embedded in the plan input |

## Layout

```
spacelift-io-spacelift-policies-example-library/
└── examples/
    └── plan/
        ├── check-blast-radius.rego
        ├── dont-allow-resource-type.rego
        ├── … (27 files total)
├── LICENSE
└── README.md
```

## Input-schema compatibility

Spacelift `plan` policies read a blended input:

- `input.terraform.resource_changes[_]` — **local** — Terraform plan JSON (parsed `terraform show -json tfplan.binary`).
- `input.terraform.third_party_metadata.checkov/kics/terrascan/tfsec/trivy/infracost` — **local** — output of scanner integrations run on the same workspace.
- `input.spacelift.run.type`, `input.spacelift.stack.labels`, `input.spacelift.commit.*` — **runtime metadata** injected by the Spacelift Go runner at policy-evaluation time.

The terraform and third-party-metadata paths are local-file-derived. The
`input.spacelift.*` metadata is a small set of context fields (run type, stack
labels, commit author, etc.) that an adapter must synthesize when running
outside Spacelift — e.g., `input.spacelift.run.type = "PROPOSED"` for a PR scan
or `"TRACKED"` for a push to the tracked branch.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that:

1. Parses `tfplan.json` into `input.terraform`.
2. Optionally merges scanner output into `input.terraform.third_party_metadata.*`.
3. Supplies minimal `input.spacelift.*` context (run type + labels).

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter required to synthesize input.terraform + input.spacelift context.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Spacelift (upstream):
# Attach each .rego as a "plan policy" on a Spacelift stack.
```

## Attribution

Copyright Spacelift, Inc. and contributors. Licensed under the MIT License.
See `LICENSE`.

**Scope note**: Upstream includes many more policy kinds (`access`, `approval`,
`login`, `notification`, `push`, `trigger`). Those consume runtime-only inputs
(Spacelift events, user actions, external API responses) and were excluded from
this curated import. To use them, consult the upstream repo directly.
