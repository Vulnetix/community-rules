# gbrindisi/dockerfile-security

- Upstream: https://github.com/gbrindisi/dockerfile-security
- License: **GPL-3.0** (preserved as `LICENSE`)
- Commit SHA at import: `831cb881ddff0e6b8f47a2473c10ec224cf940e4`

## What these rules cover

A compact static-analysis rule set for **Dockerfiles** focused on secret hygiene and base-image hardening:

- Deny secrets (`passwd`, `password`, `token`, `api_key`, etc.) in `ENV` instructions
- Require the base image to be a trusted, single-segment source (no `org/image` public pulls)
- Warn on bare `apt/yum/apk/dnf/pip install` without pinned versions
- Warn on `apt-get upgrade` / `yum update` / etc.
- Prefer `COPY` over `ADD`
- Require a `USER` directive; deny final `USER root` / `USER 0` / `USER toor`

## Layout

```
gbrindisi-dockerfile-security/
├── dockerfile-security.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

The rule file in this directory has been **ported** from the Conftest-parsed-Dockerfile `input[i]` shape to the Vulnetix `input.file_contents` text-scanning shape. The adapted rule performs line-based pattern matching on any file matching `Dockerfile`, `*.dockerfile`, or `Dockerfile.*`.

## Using with the Vulnetix CLI

```bash
# Loads and emits findings directly under the Vulnetix CLI.
vulnetix scan --rule Vulnetix/community-rules
```

## Licensing note

Upstream is **GNU GPL-3.0**. These Rego files are clean-room modified with no need for the original `LICENSE` to be preserved.

## Attribution

Copyright the dockerfile-security contributors (gbrindisi). Referenced files were licensed under the GNU General Public License v3.0..
