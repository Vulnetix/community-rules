# cds-snc/opa_checks

- Upstream: https://github.com/cds-snc/opa_checks
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `9998df3b2477836cda1762d56467cee3cda40519`
- Imported files: 17 `.rego` files from `aws_terraform/` (tests stripped)

## What these rules cover

Production OPA checks used by the **Canadian Digital Service** for AWS Terraform deployments:

- `api_gateway_integration_uri` — integration URI formatting
- `cloudfront_custom_error_response_starts_with_slash` — path-format validation
- `cloudwatch_log_metric_pattern` — metric filter pattern validation
- `container_definition_name_with_spaces` — ECS container-name hygiene
- `container_definition_template_with_trailing_comma` — ECS task-definition JSON validity
- `invald_effect` — IAM policy `Effect` field must be `Allow`/`Deny`
- `postgres_db_{main_password,main_username,name}` — RDS naming / password requirements (length, reserved words, forbidden chars)
- `reserved_words` — reserved-word detection helper
- `sg_invalid_ports` — security group port range validation
- `ssm_parameter_name_invalid` — SSM parameter naming
- `tags` — required tag enforcement
- `unscoped_service_principal` — IAM trust policy scoping
- `unsupported_lambda_runtime` — deprecated Lambda runtime detection
- `vpc_lambda_missing_eni_policy` — VPC Lambda requires ENI-creation permissions
- `waf_duplicate_priority` — WAF rule priority uniqueness

## Layout

```
cds-snc-opa-checks/
├── aws_terraform/
│   └── *.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

All checks declare `package main` and read `input.resource_changes[_]` — a
**Terraform plan JSON** (`terraform show -json plan.tfplan`). Purely local;
no cloud API calls from rule code.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that
produces the plan JSON and exposes it as the OPA `input`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter needed to produce plan JSON input.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via OPA:
terraform show -json plan.tfplan | \
  opa eval -d rules/cds-snc-opa-checks/aws_terraform/ \
    --stdin-input 'data.main'
```

## Attribution

Copyright (c) 2021 Canadian Digital Service / Service numérique canadien.
Licensed under the MIT License. See `LICENSE`.
