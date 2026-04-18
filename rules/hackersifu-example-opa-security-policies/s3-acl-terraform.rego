# Adapted from https://github.com/hackersifu/example_opa_security_policies
# Original License: Apache-2.0 (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.hackersifu_s3_acl

import rego.v1

metadata := {
	"id": "HKSF-S3-001",
	"name": "S3 bucket ACL must be private",
	"description": "Detects Terraform `aws_s3_bucket_acl` resources whose `acl` attribute is not `private`.",
	"help_uri": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [732],
	"capec": [],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "s3", "acl", "terraform"],
}

_is_tf(path) if endswith(lower(path), ".tf")

_line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

# Match resource "aws_s3_bucket_acl" "<name>" { ... acl = "<value>" ... } blocks where value != "private"
findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	blocks := regex.find_n(`(?s)resource\s+"aws_s3_bucket_acl"\s+"[^"]+"\s*\{[^{}]*?acl\s*=\s*"[^"]+"`, content, -1)
	some block in blocks
	acl_parts := regex.find_n(`acl\s*=\s*"([^"]+)"`, block, 1)
	count(acl_parts) > 0
	value := regex.replace(acl_parts[0], `.*"([^"]+)".*`, "$1")
	value != "private"
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_acl has acl=%q; must be \"private\".", [value]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": _line_of(content, offset),
		"snippet": acl_parts[0],
	}
}
