# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_36

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-36",
	"name": "Compute instance must not use the default service account",
	"description": "TF_GCP_36: google_compute_instance must configure a non-default service_account.email.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_36",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "service-account"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	not tf.has_sub_block(r.block, "service_account")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Compute instance %q has no service_account block and will use the default.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	some sa in tf.sub_blocks(r.block, "service_account")
	email := tf.string_attr(sa, "email")
	regex.match(tf.default_service_account_regexp, email)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Compute instance %q uses default service account %q.", [r.name, email]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("email=%s", [email]),
	}
}
