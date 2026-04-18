# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_16

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-16",
	"name": "Default service account must not be bound at org level",
	"description": "TF_GCP_16: google_organization_iam_binding must not include default service accounts.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_16",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam", "service-account"],
}

findings contains finding if {
	some r in tf.resources("google_organization_iam_binding")
	some m in tf.string_list_attr(r.block, "members")
	regex.match(tf.default_service_account_regexp, m)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Org IAM binding %q grants role to default service account %q.", [r.name, m]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
