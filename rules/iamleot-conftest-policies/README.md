# iamleot/conftest-policies

- Upstream: https://github.com/iamleot/conftest-policies
- License: BSD-2-Clause (preserved as `LICENSE`)
- Commit SHA at import: `3ac239cc9b7c2ae113bec7445acc69716e20a398`
- Imported files: 8 `.rego` files from `policy/` (tests stripped)

## What these rules cover

A small, multi-domain Conftest policy set using `rego.v1` and OPA `# METADATA` blocks. Four domains:

| Domain | Rules |
|---|---|
| **GitHub Actions workflows** | `name`: enforces `name:` key on workflow/job/steps. `setup_version`: enforces pinned-version policies on `actions/setup-*` steps. |
| **Dependabot** | `mandatory_toplevel_keys`: enforces required top-level keys in `dependabot.yml`. |
| **Terraform (AWS)** | `aws_iam_policy_attachment`: deny use of the exclusive-attachment resource (prefer `aws_iam_role_policy_attachment` / `user_policy_attachment` / `group_policy_attachment`). |
| **Venom test files** | `name`: enforce `name:` on test suites. `timeout`: enforce test timeout bounds. |

## Layout

```
iamleot-conftest-policies/
└── policy/
    ├── github/
    │   ├── actions/workflows/{name,setup_version,utils}/<rule>.rego
    │   └── dependabot/{mandatory_toplevel_keys,utils}/<rule>.rego
    ├── terraform/aws/aws_iam_policy_attachment/aws_iam_policy_attachment.rego
    └── venom/{name,timeout}/<rule>.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Each domain targets a different parsed-file shape fed by Conftest:

- GitHub Actions workflow YAMLs — rules check `input.name`, `input.jobs[_].name`, etc., and look up the current file via `data.conftest.file.dir` + `data.conftest.file.name`.
- Dependabot YAML — rules check `input.version`, `input.updates`, etc.
- Terraform HCL — rules check `input.resource.aws_iam_policy_attachment` (standard `conftest --parser=hcl` shape).
- Venom test YAML — rules check `input.name`, `input.testcases[_]`.

Purely local: no network, no runtime state.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that feeds each parsed-file type as `input` and provides `data.conftest.file.*` context where applicable.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter required to route each file type to the correct policy tree.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via conftest (matching each domain's parser):
conftest test --policy rules/iamleot-conftest-policies/policy/github/actions/workflows .github/workflows/ci.yml
conftest test --policy rules/iamleot-conftest-policies/policy/terraform/aws --parser=hcl main.tf
```

## Attribution

Copyright (c) 2023-2024 Leonardo Taccari. Licensed under the BSD-2-Clause License.
See `LICENSE`.
