# iamleot/conftest-policies (clean-room port)

- Upstream: https://github.com/iamleot/conftest-policies
- Commit SHA at import: `3ac239cc9b7c2ae113bec7445acc69716e20a398`

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
└── README.md
```

## Input-schema compatibility

**Ported** to the Vulnetix `input.file_contents` text-scanning shape. Each rule keys off the file path (via a `glob`/regex check for `.github/workflows/*.yml`, `.github/dependabot.yml`, `*.tf`, or Venom `testcases:`-bearing YAML) and then applies line/block pattern checks against the raw file text.

## Using with the Vulnetix CLI

```bash
# Loads and emits findings directly under the Vulnetix CLI.
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

Copyright (c) 2023-2024 Leonardo Taccari. Originally licensed under the BSD-2-Clause License.
