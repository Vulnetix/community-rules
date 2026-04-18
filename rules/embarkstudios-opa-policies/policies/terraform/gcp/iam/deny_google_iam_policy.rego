# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_04

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-04",
	"name": "google_iam_policy must not grant public access",
	"description": "TF_GCP_04: data.google_iam_policy bindings must not include allUsers or allAuthenticatedUsers.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_04",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iam", "public-exposure"],
}

# `data "google_iam_policy" "x" { binding { members = [...] } ... }`
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	pattern := `(?s)data\s+"google_iam_policy"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`
	some block in regex.find_n(pattern, content, -1)
	some b in tf.sub_blocks(block, "binding")
	some m in tf.string_list_attr(b, "members")
	m in tf.public_users
	name := _iam_policy_name(block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("data.google_iam_policy %q grants access to %q.", [name, m]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("data.google_iam_policy.%s", [name]),
	}
}

_iam_policy_name(block) := name if {
	captures := regex.find_n(`"([^"]+)"`, block, 2)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}
