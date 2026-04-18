# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_02

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-02",
	"name": "GCS bucket must not grant public IAM member",
	"description": "TF_GCP_02: google_storage_bucket_iam_member must not bind allUsers or allAuthenticatedUsers.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_02",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam", "gcs", "public-exposure"],
}

findings contains finding if {
	some r in tf.resources("google_storage_bucket_iam_member")
	m := tf.string_attr(r.block, "member")
	m in tf.public_users
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GCS bucket IAM member %q grants access to %q.", [r.name, m]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
