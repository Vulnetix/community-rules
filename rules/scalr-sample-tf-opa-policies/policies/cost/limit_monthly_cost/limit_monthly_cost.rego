# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# NOTE: Upstream depends on Scalr's cost_estimate runtime metadata
# (input.tfrun.cost_estimate.proposed_monthly_cost). Not derivable from
# static Terraform source, so this port declares metadata but never emits.

package vulnetix.rules.scalr_limit_monthly_cost

import rego.v1

metadata := {
	"id": "SCALR-COST-0001",
	"name": "Monthly plan cost must not exceed threshold (no-op under text scanning)",
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
	"tags": ["cost", "scalr-runtime"],
}

findings := set()
