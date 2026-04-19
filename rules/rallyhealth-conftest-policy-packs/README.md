# rallyhealth/conftest-policy-packs (clean-room port)

- Upstream: https://github.com/rallyhealth/conftest-policy-packs
- Commit SHA at import: `1bbfa739f27885a07cf583d8cc558ae458a89bbf`

## What these rules cover

Enterprise-scale Compliance-as-Code rule packs originally written for **Conftest**, across three domains:

- **Dockerfile** — must pull from approved private registry, no sensitive secrets in `ENV`/`ARG`.
- **Terraform** — S3 public-access block + server-side encryption, EC2 IMDSv2 required, no publicly-exposed RDS, required organizational tags.
- **package.json** — Node engine pinned to a recent LTS, package name under an approved org scope, `publishConfig.registry` set to an approved registry.

## Layout

```
rallyhealth-conftest-policy-packs/
├── policies/
│   ├── docker/
│   │   ├── deny_image_unless_from_registry/src.rego    (CTNRSEC-0001)
│   │   └── sensitive_keys_in_env_args/src.rego         (CTNRSEC-0002)
│   ├── lib/
│   │   ├── docker_functions.rego                       (vulnetix.rallyhealth.docker_utils)
│   │   ├── packages_functions.rego                     (vulnetix.rallyhealth.packages_utils)
│   │   └── util_functions.rego                         (vulnetix.rallyhealth.util)
│   ├── packages/
│   │   ├── nodejs_must_use_recent_version/src.rego     (PKGSEC-0002)
│   │   ├── nodejs_package_must_use_org_scope/src.rego  (PKGSEC-0001)
│   │   └── nodejs_use_publishConfig/src.rego           (PKGSEC-0003)
│   └── terraform/
│       ├── block_public_acls_s3/src.rego               (AWSSEC-0004)
│       ├── encrypt_s3_buckets/src.rego                 (AWSSEC-0001)
│       ├── imdsv2_required/src.rego                    (AWSSEC-0002)
│       ├── no_public_rds/src.rego                      (AWSSEC-0003)
│       └── required_tags/src.rego                      (AWSSEC-0005)
└── README.md
```

## Input-schema compatibility

**Ported** to the Vulnetix `input.file_contents` text-scanning shape:

- Dockerfile rules scan lines for `FROM` / `ENV` / `ARG` directives.
- Terraform rules use regex-based HCL block scanning (see `vulnetix.rallyhealth.util.resource_blocks`).
- `package.json` rules parse each matched file with `json.unmarshal`.

Upstream-specific behavior that cannot be faithfully replicated without external state is removed:

- `nodejs_must_use_recent_version` no longer calls `http.send` to fetch the live Node release schedule; instead it hard-codes `_min_lts_major = 20` (adjust as Node LTS moves).
- Configurable allow-lists (approved private registries, approved org scopes, approved publish registries, required tags) are now local `_*` locals at the top of each rule file — fork and tailor.

## Using with the Vulnetix CLI

```bash
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

Copyright Rally Health. Originally licensed under the MIT License.
