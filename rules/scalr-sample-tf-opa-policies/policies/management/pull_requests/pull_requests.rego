# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# NOTE: Upstream depends on Scalr VCS runtime metadata
# (input.tfrun.vcs.pull_request). Not derivable from Terraform source, so
# this port is intentionally non-firing.

package vulnetix.rules.scalr_pull_requests

import rego.v1

metadata := {
	"id": "SCALR-MGMT-0005",
	"name": "PR merged_by must differ from PR author (no-op under text scanning)",
	"description": "Upstream requires Scalr VCS runtime metadata; not applicable to file-scanning mode.",
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
	"tags": ["scalr-runtime", "vcs"],
}

findings := set()
