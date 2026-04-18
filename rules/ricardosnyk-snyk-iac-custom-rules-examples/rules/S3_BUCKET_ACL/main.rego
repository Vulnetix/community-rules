# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.ricardo_s3_bucket_acl

import rego.v1

import data.vulnetix.ricardosnyk.relations

metadata := {
	"id": "RICARDO-S3-ACL-001",
	"name": "S3 bucket ACL must be private",
	"description": "Each `aws_s3_bucket_acl` must set `acl = \"private\"`.",
	"help_uri": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
	"languages": ["terraform"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": [732],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "s3", "acl"],
}

findings contains finding if {
	some path, content in input.file_contents
	relations.is_tf(path)
	some block in relations.resource_blocks(content, "aws_s3_bucket_acl")
	m := regex.find_n(`acl\s*=\s*"([^"]+)"`, block, 1)
	count(m) > 0
	acl := regex.replace(m[0], `.*"([^"]+)".*`, "$1")
	acl != "private"
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_acl has acl=%q; must be \"private\".", [acl]),
		"artifact_uri": path,
		"severity": "critical",
		"level": "error",
		"start_line": relations.line_of(content, offset),
		"snippet": m[0],
	}
}
