# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_30_31

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-30",
	"name": "KMS crypto key must not grant public IAM access",
	"description": "TF_GCP_30/31: google_kms_crypto_key_iam_member and ..._binding must not grant allUsers or allAuthenticatedUsers.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_30",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "kms", "public-exposure"],
}

findings contains finding if {
	some r in tf.resources("google_kms_crypto_key_iam_member")
	m := tf.string_attr(r.block, "member")
	m in tf.public_users
	finding := {
		"rule_id": "EMBARK-TF-GCP-30",
		"message": sprintf("KMS crypto key IAM member %q grants access to %q.", [r.name, m]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("google_kms_crypto_key_iam_binding")
	some m in tf.string_list_attr(r.block, "members")
	m in tf.public_users
	finding := {
		"rule_id": "EMBARK-TF-GCP-31",
		"message": sprintf("KMS crypto key IAM binding %q grants access to %q.", [r.name, m]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
