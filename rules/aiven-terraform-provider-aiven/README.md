# aiven/terraform-provider-aiven

- Upstream: https://github.com/aiven/terraform-provider-aiven
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `12bf0d553d20110f975eea0a71f4ea4ba2f7cba6`
- Imported files: 6 `.rego` files from `opa/policies/` (tests stripped)

## What these rules cover

OPA policies bundled with the official **Aiven Terraform provider**. They detect conflicting Aiven-service resource changes within a single Terraform plan:

- `autoscaler_service_modification` — flag manual edits to a service that is also under the Aiven autoscaler's control
- `unique_clickhouse_grant` — disallow duplicate `aiven_clickhouse_grant` resources for the same grantee
- `unique_org_permission` — disallow duplicate `aiven_organization_permission` resources targeting the same principal
- `main.rego` — top-level aggregator that reexports the `deny` set from `conflicting/`
- `utils/terraform.rego` — helpers that walk `input.planned_values.root_module` (incl. child modules) and iterate `input.resource_changes`

Aiven service types covered: `aiven_pg`, `aiven_mysql`, `aiven_kafka`, `aiven_opensearch`, `aiven_clickhouse`, `aiven_redis`, `aiven_cassandra`, `aiven_grafana`, `aiven_dragonfly`, `aiven_valkey`, `aiven_thanos`, `aiven_flink`.

## Layout

```
aiven-terraform-provider-aiven/
├── policies/
│   ├── main.rego
│   ├── conflicting/
│   │   ├── autoscaler_service_modification.rego
│   │   ├── doc.rego
│   │   ├── unique_clickhouse_grant.rego
│   │   └── unique_org_permission.rego
│   └── utils/
│       └── terraform.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Rules consume a **Terraform plan JSON** (`terraform show -json plan.tfplan`) at
`input.planned_values.root_module.resources` and `input.resource_changes`.
Entirely local — no cloud API calls from rule code.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that
emits the plan JSON (typically by running `terraform plan -out=... && terraform show -json`)
and exposes it as the OPA `input`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter needed to produce plan JSON input.
vulnetix scan --rule Vulnetix/community-rules

# Direct use with OPA:
terraform show -json plan.tfplan | \
  opa eval -d rules/aiven-terraform-provider-aiven/policies/ \
    --stdin-input 'data.aiven.main.deny'
```

## Attribution

Copyright (c) 2017 jelmersnoeck; Copyright (c) 2018-2024 Aiven, Helsinki, Finland.
Licensed under the MIT License. See `LICENSE`.
