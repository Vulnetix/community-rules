# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_19

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-19",
	"name": "GKE node pool must enable auto_upgrade",
	"description": "TF_GCP_19: google_container_node_pool must set management.auto_upgrade = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_19",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "patching"],
}

findings contains finding if {
	some r in tf.resources("google_container_node_pool")
	not _auto_upgrade_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node pool %q does not enable auto_upgrade.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_auto_upgrade_enabled(block) if {
	some sub in tf.sub_blocks(block, "management")
	regex.match(`(?m)^\s*auto_upgrade\s*=\s*true\b`, sub)
}
