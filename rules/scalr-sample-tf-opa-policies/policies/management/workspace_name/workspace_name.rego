# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# NOTE: Upstream depends on Scalr runtime workspace.name metadata.

package vulnetix.rules.scalr_workspace_name

import rego.v1

metadata := {
	"id": "SCALR-MGMT-0010",
	"name": "Workspace name suffix must be `-dev` (no-op under text scanning)",
	"description": "Upstream requires Scalr workspace runtime metadata; not applicable to file-scanning mode.",
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
