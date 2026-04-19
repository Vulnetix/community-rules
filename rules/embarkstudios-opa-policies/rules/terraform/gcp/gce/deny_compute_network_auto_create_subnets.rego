# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_42

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-42",
	"name": "Compute network must disable auto_create_subnetworks",
	"description": "TF_GCP_42: google_compute_network must set auto_create_subnetworks = false.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_42",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1188"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "network"],
}

findings contains finding if {
	some r in tf.resources("google_compute_network")
	tf.is_not_false(r.block, "auto_create_subnetworks")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Compute network %q does not disable auto_create_subnetworks.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
