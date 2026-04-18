# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# NOTE: Upstream depends on Scalr plan-action metadata (resource.change.actions)
# and `scalr_workspace` state — not derivable from static Terraform source.

package vulnetix.rules.scalr_workspace_destroy

import rego.v1

metadata := {
	"id": "SCALR-MGMT-0008",
	"name": "Cannot destroy Scalr workspace with active state (no-op under text scanning)",
	"description": "Upstream requires plan-action metadata; not applicable to file-scanning mode.",
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
	"tags": ["scalr-runtime", "workspace"],
}

findings := set()
