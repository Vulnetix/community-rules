# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_06

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-06",
	"name": "google_project must not auto-create the default network",
	"description": "TF_GCP_06: google_project must set auto_create_network = false.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_06",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1188"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "network", "hardening"],
}

findings contains finding if {
	some r in tf.resources("google_project")
	tf.is_not_false(r.block, "auto_create_network")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_project %q does not disable auto_create_network.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
