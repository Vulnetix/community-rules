# gbrindisi/dockerfile-security

- Upstream: https://github.com/gbrindisi/dockerfile-security
- License: **GPL-3.0** (preserved as `LICENSE`)
- Commit SHA at import: `831cb881ddff0e6b8f47a2473c10ec224cf940e4`
- Imported files: 1 `.rego` file (`dockerfile-security.rego`)

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

Operates on a **Conftest-parsed Dockerfile** — `input[i]` is a list of `{Cmd, Value, ...}` instruction objects. Purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to tokenize each Dockerfile from `input.file_contents[path]` into the `{Cmd, Value}` list shape and rebind `input`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Conftest (upstream path):
conftest test --policy rules/gbrindisi-dockerfile-security/ Dockerfile
```

## Licensing note

Upstream is **GNU GPL-3.0**. These Rego files are redistributed unmodified with the original `LICENSE` preserved. Downstream consumers should review GPL-3.0 obligations before combining with code under incompatible licenses.

## Attribution

Copyright the dockerfile-security contributors (gbrindisi). Licensed under the GNU General Public License v3.0. See `LICENSE`.
