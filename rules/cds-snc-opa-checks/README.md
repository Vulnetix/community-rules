# cds-snc/opa_checks

- Upstream: https://github.com/cds-snc/opa_checks
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `9998df3b2477836cda1762d56467cee3cda40519`
- Imported files: 15 rule `.rego` files + 2 helper packages (tests stripped)

## What these rules cover

Production OPA checks used by the **Canadian Digital Service** for AWS Terraform deployments:

- `api_gateway_integration_uri` — integration URI formatting
- `cloudfront_custom_error_response_starts_with_slash` — path-format validation
- `cloudwatch_log_metric_pattern` — metric filter pattern validation
- `container_definition_name_with_spaces` — ECS container-name hygiene
- `container_definition_template_with_trailing_comma` — ECS task-definition JSON validity
- `invald_effect` — IAM policy `Effect` field must be `Allow`/`Deny`
- `postgres_db_{main_password,main_username,name}` — RDS naming / password requirements
- `sg_invalid_ports` — security group port range validation
- `ssm_parameter_name_invalid` — SSM parameter naming
- `tags` — required CostCentre+Terraform tag enforcement
- `unscoped_service_principal` — IAM trust policy scoping
- `unsupported_lambda_runtime` — deprecated Lambda runtime detection
- `vpc_lambda_missing_eni_policy` — VPC Lambda requires ENI-creation permissions
- `waf_duplicate_priority` — WAFv2 rule priority uniqueness

## Layout

```
cds-snc-opa-checks/
├── aws_terraform/
│   ├── _lib.rego               (vulnetix.cds_snc.tf — HCL scanning helpers)
│   ├── reserved_words.rego     (vulnetix.cds_snc.reserved_words — Postgres reserved words)
│   └── *.rego                  (one per rule)
├── LICENSE
└── README.md
```

## Input-schema compatibility

**Ported** to the Vulnetix `input.file_contents` text-scanning shape. Upstream
rules consumed `terraform show -json plan.tfplan` and walked
`input.resource_changes[_]`. Under Vulnetix the scanner never invokes
Terraform, so this port replaces the plan-JSON traversal with regex-based HCL
block scanning over raw `.tf` source.

Limitations of the port (vs. the original plan-based checks):

- References and interpolations (`aws_iam_role.foo.arn`, `var.x`, locals) are not
  resolved — attribute-value checks look only at literal values.
- Checks that traversed `input.configuration.root_module` (the VPC Lambda /
  ENI-policy check) now match by attribute pattern rather than the plan's
  reference graph.
- `unsupported_lambda_runtime` has its allow-list refreshed against current AWS
  supported runtimes (as of 2026-04).

## Using with the Vulnetix CLI

```bash
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

Copyright (c) 2021 Canadian Digital Service / Service numérique canadien.
Licensed under the MIT License. See `LICENSE`.
