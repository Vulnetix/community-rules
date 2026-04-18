# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_22

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-22",
	"name": "GKE nodes must enable secure boot",
	"description": "TF_GCP_22: google_container_node_pool must set node_config.shielded_instance_config.enable_secure_boot = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_22",
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
	some r in tf.resources("google_container_node_pool")
	not regex.match(`(?m)^\s*enable_secure_boot\s*=\s*true\b`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node pool %q does not enable secure boot.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
