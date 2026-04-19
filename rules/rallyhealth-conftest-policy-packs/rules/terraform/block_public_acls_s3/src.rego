# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.rally_s3_block_public_acls

import rego.v1

import data.vulnetix.rallyhealth.util

metadata := {
	"id": "AWSSEC-0004",
	"name": "S3 buckets must have public access block configured",
	"description": "Every `aws_s3_bucket` must have a matching `aws_s3_bucket_public_access_block` with `block_public_acls = true`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284, 732],
	"capec": [],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "s3", "public-access"],
}

findings contains finding if {
	some path, content in input.file_contents
	util.is_tf(path)
	some block in util.resource_blocks(content, "aws_s3_bucket")
	bucket_name := util.resource_name(block)
	not _has_public_access_block(content, bucket_name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no matching aws_s3_bucket_public_access_block resource.", [bucket_name]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": bucket_name,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	util.is_tf(path)
	some block in util.resource_blocks(content, "aws_s3_bucket_public_access_block")
	not regex.match(`(?m)^\s*block_public_acls\s*=\s*true\s*$`, block)
	resource := util.resource_name(block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_public_access_block %q does not set block_public_acls = true.", [resource]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": resource,
	}
}

_has_public_access_block(content, bucket_name) if {
	some block in util.resource_blocks(content, "aws_s3_bucket_public_access_block")
	regex.match(sprintf(`aws_s3_bucket\.%s(\.|\b)`, [bucket_name]), block)
}
