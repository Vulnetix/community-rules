# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_14

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-14",
	"name": "Compute firewall must not allow unrestricted source range",
	"description": "TF_GCP_14: google_compute_firewall with allow rules must not use source_ranges containing 0.0.0.0/0.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_14",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "network", "firewall"],
}

findings contains finding if {
	some r in tf.resources("google_compute_firewall")
	tf.has_sub_block(r.block, "allow")
	some s in tf.string_list_attr(r.block, "source_ranges")
	s == "0.0.0.0/0"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Firewall %q allows 0.0.0.0/0 in source_ranges.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
