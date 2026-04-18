# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_40

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-40",
	"name": "Compute project metadata must not set project-wide SSH keys",
	"description": "TF_GCP_40: google_compute_project_metadata / _item must not define ssh-keys.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_40",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "ssh"],
}

findings contains finding if {
	some r in tf.resources("google_compute_project_metadata")
	regex.match(`(?m)^\s*"ssh-keys"\s*=`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_project_metadata %q sets project-wide ssh-keys.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("google_compute_project_metadata_item")
	tf.string_attr(r.block, "key") == "ssh-keys"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_project_metadata_item %q sets project-wide ssh-keys.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
