# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_34

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-34",
	"name": "GKE cluster must enable shielded nodes",
	"description": "TF_GCP_34: google_container_cluster must set enable_shielded_nodes = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_34",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1188"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "shielded"],
}

findings contains finding if {
	some r in tf.resources("google_container_cluster")
	tf.is_not_true(r.block, "enable_shielded_nodes")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q does not enable shielded nodes.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
