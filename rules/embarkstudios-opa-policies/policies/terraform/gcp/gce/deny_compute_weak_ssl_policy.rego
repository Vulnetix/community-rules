# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_11

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-11",
	"name": "Compute SSL policy must use MODERN or RESTRICTED profile",
	"description": "TF_GCP_11: google_compute_ssl_policy.profile must be MODERN or RESTRICTED.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_11",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "ssl", "cryptography"],
}

findings contains finding if {
	some r in tf.resources("google_compute_ssl_policy")
	profile := tf.string_attr(r.block, "profile")
	not profile in {"MODERN", "RESTRICTED"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SSL policy %q uses weak profile %q.", [r.name, profile]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("profile=%s", [profile]),
	}
}
