# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_27

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-27",
	"name": "GKE node pool must use COS image type",
	"description": "TF_GCP_27: google_container_node_pool node_config.image_type must be cos or cos_containerd.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_27",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "hardening"],
}

allowed_image_types := {"cos", "cos_containerd"}

findings contains finding if {
	some r in tf.resources("google_container_node_pool")
	not _has_allowed_image_type(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node pool %q image_type is not cos/cos_containerd.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_allowed_image_type(block) if {
	some sub in tf.sub_blocks(block, "node_config")
	img := lower(tf.string_attr(sub, "image_type"))
	img in allowed_image_types
}
