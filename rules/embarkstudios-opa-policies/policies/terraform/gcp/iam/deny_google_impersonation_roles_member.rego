# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_17

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-17",
	"name": "Impersonation roles must not be granted at org/folder/project via iam_member",
	"description": "TF_GCP_17: iam_member must not grant roles/iam.serviceAccountTokenCreator or roles/iam.serviceAccountUser.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_17",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": ["T1078"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam", "privilege-escalation"],
}

findings contains finding if {
	types := {"google_organization_iam_member", "google_folder_iam_member", "google_project_iam_member"}
	some t in types
	some r in tf.resources(t)
	role := tf.string_attr(r.block, "role")
	role in tf.impersonation_roles
	m := tf.string_attr(r.block, "member")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q grants impersonation role %q to %q.", [t, r.name, role, m]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
