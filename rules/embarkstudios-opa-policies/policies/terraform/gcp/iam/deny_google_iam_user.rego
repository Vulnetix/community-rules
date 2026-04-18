# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_44

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-44",
	"name": "IAM must not bind individual users at org/folder/project level",
	"description": "TF_GCP_44: google_{organization,folder,project}_iam_member must not bind user: principals (prefer groups/service accounts).",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_44",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam"],
}

findings contains finding if {
	types := {"google_organization_iam_member", "google_folder_iam_member", "google_project_iam_member"}
	some t in types
	some r in tf.resources(t)
	m := tf.string_attr(r.block, "member")
	startswith(m, "user:")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q binds individual user %q.", [t, r.name, m]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
