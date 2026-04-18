# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_28

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-28",
	"name": "GKE cluster must set authenticator_groups_config.security_group",
	"description": "TF_GCP_28: authenticator_groups_config.security_group must match gke-security-groups@*.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_28",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "authz"],
}

findings contains finding if {
	some r in tf.resources("google_container_cluster")
	not _has_security_group(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has no valid authenticator_groups_config.security_group.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_security_group(block) if {
	some sub in tf.sub_blocks(block, "authenticator_groups_config")
	sg := tf.string_attr(sub, "security_group")
	regex.match(`^gke-security-groups@.*`, sg)
}
