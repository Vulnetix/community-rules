# community-rules

A curated, attributed collection of community Rego policies, organized for use with the [Vulnetix CLI](https://github.com/Vulnetix/cli) `--rule` flag.

## Layout

All rules live under `rules/` so that the Vulnetix CLI will discover them:

```
community-rules/
└── rules/
    └── <normalized-source>/
        ├── README.md   ← attribution, license, summary, usage
        └── *.rego      ← rule files sourced from the upstream repo
```

Each `<normalized-source>` directory corresponds to one upstream repository. The naming convention is `<org>-<repo>`, lower-cased with non-alphanumerics collapsed to `-`.

## Usage

Load the whole collection from this repository:

```bash
vulnetix scan --rule Vulnetix/community-rules
```

The Vulnetix CLI walks every `.rego` file under `rules/` recursively, so all subdirectories are picked up automatically.

To use a specific upstream's rules only, create a fork or a thin copy that keeps just one subdirectory under `rules/`.

## Important compatibility notes

Most upstream Rego rule collections were written for other tools — OPA/Gatekeeper, Conftest, Regula, Kubescape — and expect different `input` schemas:

| Tool | `input` shape |
|---|---|
| **Vulnetix** (this CLI) | `{ "file_contents": { "<path>": "<full file text>" } }` |
| Conftest | Parsed YAML/JSON/Terraform/Dockerfile document |
| Gatekeeper | Kubernetes admission review object |
| Regula | Terraform plan / CloudFormation / Kubernetes manifest object |

Rules in this repository that were written against a different `input` schema **will load but will not produce findings** when run under the Vulnetix CLI unless adapted. Each subdirectory README documents the upstream's expected input and whether/how the rules are directly usable.

For rules that are adapted or wrapped for Vulnetix compatibility, the subdirectory README describes the transformation.

## Attribution and licensing

Each subdirectory preserves the upstream's copyright and license. See each subdirectory `README.md` for the source URL, original license, and commit SHA at the time of import. Nothing in this collection supersedes an upstream's license — if a rule is Apache-2.0 upstream, it is Apache-2.0 here.
