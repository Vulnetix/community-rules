# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# NOTE: Upstream depends on Scalr runtime identity (input.tfrun.created_by.username,
# input.tfrun.vcs.commit.author.email). Not derivable from Terraform source.

package vulnetix.rules.scalr_check_user

import rego.v1

metadata := {
	"id": "SCALR-USER-0001",
	"name": "Run initiator must be allow-listed (no-op under text scanning)",
	"description": "Upstream requires Scalr user/VCS runtime metadata; not applicable to file-scanning mode.",
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
	"tags": ["scalr-runtime", "user"],
}

findings := set()
