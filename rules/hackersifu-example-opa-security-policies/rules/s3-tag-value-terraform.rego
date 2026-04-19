# Adapted from https://github.com/hackersifu/example_opa_security_policies
# Original License: Apache-2.0 (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.hackersifu_s3_required_tag

import rego.v1

metadata := {
	"id": "HKSF-S3-002",
	"name": "S3 bucket must carry a required tag",
	"description": "Example rule: each `aws_s3_bucket` should declare a `tags` block containing an `Environment` key (tailor this in your fork).",
	"help_uri": "https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html",
	"languages": ["terraform"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "s3", "tagging", "terraform"],
}

_required_tag_key := "Environment"

_is_tf(path) if endswith(lower(path), ".tf")

_line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

# Capture aws_s3_bucket blocks missing required tag key.
findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	blocks := regex.find_n(`(?s)resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{[^{}]*?\}`, content, -1)
	some block in blocks
	not regex.match(sprintf(`(?s)tags\s*=\s*\{[^}]*"%s"\s*=`, [_required_tag_key]), block)
	offset := indexof(content, block)
	name_parts := regex.find_n(`"aws_s3_bucket"\s+"([^"]+)"`, block, 1)
	count(name_parts) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %s is missing required tag %q.", [name_parts[0], _required_tag_key]),
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": _line_of(content, offset),
		"snippet": name_parts[0],
	}
}
