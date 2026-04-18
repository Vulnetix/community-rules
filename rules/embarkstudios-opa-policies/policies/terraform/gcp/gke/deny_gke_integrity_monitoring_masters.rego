# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_32

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-32",
	"name": "GKE must enable integrity monitoring",
	"description": "TF_GCP_32: google_container_cluster must set node_config.shielded_instance_config.enable_integrity_monitoring = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_32",
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
	not regex.match(`(?m)^\s*enable_integrity_monitoring\s*=\s*true\b`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q does not enable integrity monitoring.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
