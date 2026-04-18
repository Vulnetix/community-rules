# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_50

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-50",
	"name": "Artifact Registry must not grant public IAM binding",
	"description": "TF_GCP_50: google_artifact_registry_repository_iam_binding must not bind allUsers or allAuthenticatedUsers.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_50",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam", "artifact-registry", "public-exposure"],
}

findings contains finding if {
	some r in tf.resources("google_artifact_registry_repository_iam_binding")
	some m in tf.string_list_attr(r.block, "members")
	m in tf.public_users
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Artifact Registry IAM binding %q grants access to %q.", [r.name, m]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
