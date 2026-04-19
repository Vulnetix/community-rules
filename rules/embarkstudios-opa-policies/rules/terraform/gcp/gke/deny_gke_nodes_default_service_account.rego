# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_41

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-41",
	"name": "GKE node pool must not use default service account",
	"description": "TF_GCP_41: google_container_node_pool node_config.service_account must be set and not default.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_41",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "service-account"],
}

findings contains finding if {
	some r in tf.resources("google_container_node_pool")
	_uses_default_sa(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node pool %q uses the default service account.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_uses_default_sa(block) if {
	not _has_custom_sa(block)
}

_has_custom_sa(block) if {
	some sub in tf.sub_blocks(block, "node_config")
	sa := tf.string_attr(sub, "service_account")
	sa != ""
	not regex.match(tf.default_service_account_regexp, sa)
}
