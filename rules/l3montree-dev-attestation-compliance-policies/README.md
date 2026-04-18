# l3montree-dev/attestation-compliance-policies

- Upstream: https://github.com/l3montree-dev/attestation-compliance-policies
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `11781c0726fb7e8ab7181fc0f4309e8642bd97e6`
- Imported files: 14 `.rego` files from upstream `policies/`

## What these rules cover

A community-driven rule set for validating **SLSA / in-toto attestation files** (local JSON documents) against software supply-chain compliance controls. Each rule has Konstraint-style `# METADATA` with `predicateType`, `complianceFrameworks` (ISO 27001, DORA, etc.), and `priority` annotations.

Examples:

- `branch_protection_enabled` — branch protection on the default branch
- `build_from_signed_source` — commits of the build source are signed
- `ci_image_has_digest_set` — CI image is pinned by digest
- `code_review_for_changes_on_default_branch` — PR review present
- `container_scanning_executed`, `software_composition_analysis_executed`, `secret_scanning_executed`
- `current_sbom_is_present`
- `notification_channel_for_new_vulnerabilities`
- `only_osi_approved_licenses`
- `security_policy_present_in_repo`, `signed_off_commit`, `cia_requirements_set_for_asset`
- `author_committer_email_is_from_org` (example — upstream uses `l3montree.com`; override when reusing)

## Layout

```
l3montree-dev-attestation-compliance-policies/
├── policies/
│   └── <control>.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Operates on an **in-toto Statement** bound to `input` — i.e., a parsed local attestation JSON file. Every rule keys off `input.predicateType` and then reads `input.predicate.*`. Purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to JSON-parse each attestation from `input.file_contents[path]` and rebind `input` to the parsed in-toto Statement.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via OPA against a local attestation file:
opa eval --input attestation.json \
         --data rules/l3montree-dev-attestation-compliance-policies/policies/ \
         'data.compliance.compliant'
```

## Attribution

Copyright 2025 L3montree UG (haftungsbeschränkt). Licensed under the MIT License. See `LICENSE`.
