# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_09

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-09",
	"name": "BigQuery dataset must not grant public IAM binding",
	"description": "TF_GCP_09: google_bigquery_dataset_iam_binding must not bind allUsers or allAuthenticatedUsers.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_09",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam", "bigquery", "public-exposure"],
}

findings contains finding if {
	some r in tf.resources("google_bigquery_dataset_iam_binding")
	some m in tf.string_list_attr(r.block, "members")
	m in tf.public_users
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("BigQuery dataset IAM binding %q grants access to %q.", [r.name, m]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
