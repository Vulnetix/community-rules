# confluentinc/opa_for_confluent_cloud

- Upstream: https://github.com/confluentinc/opa_for_confluent_cloud
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `efae9529b5330bc8f2fb7e71afcc54c7e0f3c744`
- Imported files: `policies/` tree (tests stripped)

## What these rules cover

Official Confluent guardrails for **Terraform plans** that touch the **Confluent Cloud Terraform provider** (`confluentinc/confluent`). Rules include:

- API keys must be owned by a service account (not a user account)
- API key names must match an approved regex
- Service account names must match an approved regex
- Only approved RBAC role bindings
- Only approved resource types can be managed by Terraform
- Kafka clusters must be in approved clouds / regions
- Connectors restricted to an approved catalog
- Topic partition count and retention period within enforced ranges

## Layout

```
confluentinc-opa-for-confluent-cloud/
└── policies/
    └── <policy_name>/
        └── <policy_name>.rego
```

## Input-schema compatibility

Operates on a **local Terraform plan JSON** (`terraform show -json plan.out > plan.json`). The top of every rule auto-detects whether the plan was emitted by Terraform Cloud or the Terraform CLI:

```rego
tfplan := input if { input.terraform_version }
         else := input.plan if { input.plan.terraform_version }
```

Then iterates `tfplan.resource_changes[_]`. Purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to JSON-parse a `plan.json` from `input.file_contents[path]` and rebind `input` to the parsed document.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via OPA:
terraform show -json plan.out > plan.json
opa eval --input plan.json \
         --data rules/confluentinc-opa-for-confluent-cloud/policies/ \
         'data.confluent[_].deny'
```

## Attribution

Copyright Confluent, Inc. Licensed under the Apache License, Version 2.0. See `LICENSE`.
