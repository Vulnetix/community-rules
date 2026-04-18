# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_var_desc

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-MGMT-0003",
	"name": "Every Terraform variable must declare a description",
	"description": "Each `variable \"NAME\" { ... }` block must include a non-empty `description = \"...\"`.",
	"help_uri": "https://developer.hashicorp.com/terraform/language/values/variables#arguments",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "variables", "documentation"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)variable\s+"[^"]+"\s*\{(?:[^{}]|\{[^{}]*\})*?\}`, content, -1)
	some block in blocks
	desc := tf.string_attr(block, "description")
	desc == ""
	header := regex.find_n(`variable\s+"[^"]+"`, block, 1)
	count(header) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s has no non-empty description.", [header[0]]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": header[0],
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)variable\s+"[^"]+"\s*\{(?:[^{}]|\{[^{}]*\})*?\}`, content, -1)
	some block in blocks
	not regex.match(`(?m)^\s*description\s*=`, block)
	header := regex.find_n(`variable\s+"[^"]+"`, block, 1)
	count(header) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s has no description attribute.", [header[0]]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": header[0],
	}
}
