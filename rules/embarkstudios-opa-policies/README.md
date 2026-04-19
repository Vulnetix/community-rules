# EmbarkStudios/opa-policies (Vulnetix clean-room port)

- Upstream: https://github.com/EmbarkStudios/opa-policies
- Commit SHA at import: `c6377cad4660e010dc0bb01bb1a5fcf04efa60be`

The upstream repository ships three policy suites designed to be run via
`conftest` against pre-parsed inputs: Terraform HCL (GCP), Kubernetes manifests,
and Dockerfiles. Under Vulnetix every rule analyses raw text via
`input.file_contents` (map of file path → file content), so this port replaces
the upstream input schema with helpers that parse the text directly.

## Layout

```
_lib/
  docker.rego   # vulnetix.embark.docker — Dockerfile instruction parser
  k8s.rego      # vulnetix.embark.k8s    — multi-doc YAML workload parser
  tf.rego       # vulnetix.embark.tf     — regex-based HCL resource scanner
policies/
  docker/         # 7 Dockerfile rules
  kubernetes/     # 20 Kubernetes rules
  terraform/gcp/  # 51 Terraform GCP rules (ar/, bq/, cloudsql/, gce/, gcs/,
                  #  gke/, iam/, iap/, kms/, memorystore/, org/, project/)
```

Each rule file is a standalone Rego module declaring a `metadata` object
(id, name, severity, help_uri, cwe, …) and a `findings` partial set shaped
to the Vulnetix SAST rule schema.

## Rule ID mapping

Upstream IDs use the prefix `DOCKER_`, `K8S_`, or `TF_GCP_`. Vulnetix IDs are
`EMBARK-<PREFIX>-<NN>` preserving the upstream number, e.g. `K8S_10` ↔
`EMBARK-K8S-10`. The original wiki link is retained in `help_uri`.

## Caveats

- The Terraform HCL helper does regex-based block extraction; it is best-effort
  and does not resolve variables, locals, or module references. Findings are
  accurate for attributes set inline in resource blocks.
- The Kubernetes helper splits multi-document YAML on `---` and parses each doc
  with `yaml.unmarshal`. Templated Helm charts (e.g. with `{{ .Values.x }}`
  tokens) will not parse — consistent with upstream behaviour.
- The Dockerfile helper joins `\<newline>` continuations then splits on
  whitespace; it does not evaluate `ARG` or `ENV` substitutions.
