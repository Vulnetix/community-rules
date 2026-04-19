# Adapted from https://github.com/iamleot/conftest-policies
# Original License: BSD-2-Clause (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.iamleot_iam_policy_attachment

import rego.v1

metadata := {
	"id": "IAMLEOT-TF-IAM-001",
	"name": "Prohibit aws_iam_policy_attachment (exclusive attachment)",
	"description": "`aws_iam_policy_attachment` creates an *exclusive* attachment: if the same policy is attached elsewhere, those attachments will be revoked. Use `aws_iam_{role,user,group}_policy_attachment` instead.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy_attachment",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [732],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "iam", "terraform"],
}

_is_tf(path) if endswith(lower(path), ".tf")

_line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	matches := regex.find_n(`(?m)^\s*resource\s+"aws_iam_policy_attachment"\s+"([^"]+)"`, content, -1)
	some match in matches
	offset := indexof(content, match)
	name_parts := regex.find_n(`"aws_iam_policy_attachment"\s+"([^"]+)"`, match, 1)
	count(name_parts) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Use `aws_iam_{role,user,group}_policy_attachment` instead of `aws_iam_policy_attachment` %q (exclusive attachment).", [name_parts[0]]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": _line_of(content, offset),
		"snippet": trim_space(match),
	}
}
