# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_29

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-29",
	"name": "GKE cluster must remove the default node pool",
	"description": "TF_GCP_29: google_container_cluster must set remove_default_node_pool = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_29",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "hardening"],
}

findings contains finding if {
	some r in tf.resources("google_container_cluster")
	tf.is_not_true(r.block, "remove_default_node_pool")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q does not set remove_default_node_pool=true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
