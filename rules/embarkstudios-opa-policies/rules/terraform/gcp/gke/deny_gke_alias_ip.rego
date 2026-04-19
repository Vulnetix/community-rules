# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_05

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-05",
	"name": "GKE cluster must enable alias IPs",
	"description": "TF_GCP_05: google_container_cluster must declare an ip_allocation_policy block.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_05",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "network"],
}

findings contains finding if {
	some r in tf.resources("google_container_cluster")
	not tf.has_sub_block(r.block, "ip_allocation_policy")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has no ip_allocation_policy (alias IPs disabled).", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
