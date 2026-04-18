# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# NOTE: Upstream depends on Scalr runtime workspace.tags metadata.

package vulnetix.rules.scalr_workspace_tags

import rego.v1

metadata := {
	"id": "SCALR-MGMT-0011",
	"name": "Workspace must carry provider-name tag (no-op under text scanning)",
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
	"tags": ["scalr-runtime", "workspace", "tagging"],
}

findings := set()
