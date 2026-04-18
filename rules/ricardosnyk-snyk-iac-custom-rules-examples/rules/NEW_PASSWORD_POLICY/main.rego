# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.ricardo_password_policy

import rego.v1

import data.vulnetix.ricardosnyk.relations

metadata := {
	"id": "RICARDO-IAM-PWD-001",
	"name": "IAM password policy minimum length",
	"description": "`aws_iam_account_password_policy` should declare `minimum_password_length >= 17`.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [521],
	"capec": ["CAPEC-16"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "iam", "password-policy"],
}

_min_length := 17

findings contains finding if {
	some path, content in input.file_contents
	relations.is_tf(path)
	some block in relations.resource_blocks(content, "aws_iam_account_password_policy")
	length_match := regex.find_n(`minimum_password_length\s*=\s*([0-9]+)`, block, 1)
	count(length_match) > 0
	length_str := regex.replace(length_match[0], `\D`, "")
	to_number(length_str) < _min_length
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("minimum_password_length is %s; must be at least %d.", [length_str, _min_length]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": relations.line_of(content, offset),
		"snippet": length_match[0],
	}
}
