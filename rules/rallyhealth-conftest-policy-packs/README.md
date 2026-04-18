# rallyhealth/conftest-policy-packs

- Upstream: https://github.com/rallyhealth/conftest-policy-packs
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `1bbfa739f27885a07cf583d8cc558ae458a89bbf`
- Imported files: 13 `.rego` files (tests stripped), plus `data/` for approved registries and configurable allow-lists

## What these rules cover

Enterprise-scale Compliance-as-Code rule packs for **Conftest**. Targets local files across three domains:

- **Dockerfile** — must pull from approved private registry, no sensitive secrets in `ENV`/`ARG`, no `sudo`, no wildcard `ADD` of remote tarballs, pin base image digests.
- **Terraform** — AWS tagging, S3 bucket public access, provider version pinning, approved-module-source allow-listing.
- **package.json** — no disallowed dependency sources (non-approved registries), license allow-list enforcement.

## Layout

```
rallyhealth-conftest-policy-packs/
├── policies/
│   ├── docker/
│   │   └── <policy_id>/src.rego
│   ├── lib/                     ← shared helpers (docker_utils, util_functions, packages_functions)
│   ├── packages/
│   └── terraform/
├── data/                        ← approved-registry lists, excepted env keys
├── LICENSE
└── README.md
```

Each rule follows a Conftest convention: `<policy>/src.rego` declares the rule with a `policyID`, optional `data.<allowlist>` references, and a `violation[{...}]` rule.

## Input-schema compatibility

Operates on **local files** parsed by Conftest:

- Dockerfile → Conftest's Dockerfile parser fills `input` as an array of `{Cmd, Value}` records.
- `*.tf` → HCL parsed.
- `package.json` → JSON parsed directly into `input`.

All local-only. No live API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but won't fire until an adapter parses each Dockerfile / HCL / package.json from `input.file_contents[path]` and rebinds `input` + `conftest.file.name`. The rules' domain semantics remain purely local.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Conftest:
conftest test --policy rules/rallyhealth-conftest-policy-packs/policies/ \
              --data   rules/rallyhealth-conftest-policy-packs/data/ \
              Dockerfile
```

## Attribution

Copyright Rally Health. Licensed under the MIT License. See `LICENSE`.
