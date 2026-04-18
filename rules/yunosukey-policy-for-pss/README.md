# YunosukeY/policy-for-pss

- Upstream: https://github.com/YunosukeY/policy-for-pss
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `3acc915c14923453f918e39eb7c24d4b5e4fb540`
- Imported files: 20 `.rego` files from `pod-security-standards/` (tests stripped)

## What these rules cover

A Conftest-style rego implementation of the **Kubernetes Pod Security Standards** ([PSS](https://kubernetes.io/docs/concepts/security/pod-security-standards/)). Covers the two enforceable PSS profiles:

**Baseline** (prevents known privilege escalations):

- Host namespaces (hostPID/hostIPC/hostNetwork)
- HostProcess containers
- Privileged containers
- Capabilities (disallowed baseline)
- Host paths
- Host ports
- AppArmor profiles
- SELinux options
- `/proc` mount types
- Seccomp types
- Sysctls (disallowed)

**Restricted** (highly-restrictive, current pod hardening best practices):

- Privilege escalation
- Disallowed capabilities (restricted set)
- Seccomp types (restricted)
- Run as root (container + pod level)
- Volume types

## Layout

```
yunosukey-policy-for-pss/
└── pod-security-standards/
    ├── deny.rego                    # aggregator: imports both baseline + restricted
    └── lib/
        ├── baseline/<rule>/violation_<topic>.rego
        ├── restricted/<rule>/violation_<topic>.rego
        ├── k8s/k8s.rego              # helpers: workload_resources, pod(), containers()
        └── wrapper/wrapper.rego      # dual-mode Gatekeeper/local
├── LICENSE
└── README.md
```

## Input-schema compatibility

The library's `wrapper.rego` implements the **dual-mode Gatekeeper/local** pattern:

```rego
is_gatekeeper if { input.review.object }
resource(object) := object.review.object if { is_gatekeeper }
resource(object) := object                 if { not is_gatekeeper }
```

This means rules work both:

- **Locally**: fed a parsed K8s YAML manifest directly as `input` (the standard conftest shape).
- **In-cluster via Gatekeeper**: admission-controller webhook.

Purely local: no cluster API calls, no HTTP fetches from rule code.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that parses each `*.yaml` manifest into `input`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter required to feed parsed K8s manifest as input.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via conftest:
conftest test --policy rules/yunosukey-policy-for-pss/pod-security-standards ./manifests

# Or via Gatekeeper (admission-time, in-cluster).
```

## Attribution

Copyright YunosukeY. Licensed under the MIT License. See `LICENSE`.
