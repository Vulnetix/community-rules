# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# NOTE: Upstream depends on Scalr runtime workspace + cost_estimate metadata.

package vulnetix.rules.scalr_workspace_environment_type

import rego.v1

metadata := {
	"id": "SCALR-MGMT-0009",
	"name": "Dev workspace monthly cost cap (no-op under text scanning)",
	"description": "Upstream requires Scalr cost_estimate runtime metadata; not applicable to file-scanning mode.",
	"help_uri": "https://github.com/Scalr/sample-tf-opa-policies",
	"languages": ["terraform"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["scalr-runtime", "cost"],
}

findings := set()
