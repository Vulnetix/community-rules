# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_21

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-21",
	"name": "GKE node pool must enable auto_repair",
	"description": "TF_GCP_21: google_container_node_pool must set management.auto_repair = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_21",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "reliability"],
}

findings contains finding if {
	some r in tf.resources("google_container_node_pool")
	not _auto_repair_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node pool %q does not enable auto_repair.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_auto_repair_enabled(block) if {
	some sub in tf.sub_blocks(block, "management")
	regex.match(`(?m)^\s*auto_repair\s*=\s*true\b`, sub)
}
