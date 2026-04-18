# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.rally_s3_encrypt

import rego.v1

import data.vulnetix.rallyhealth.util

metadata := {
	"id": "AWSSEC-0001",
	"name": "S3 buckets must enable server-side encryption",
	"description": "`aws_s3_bucket` resources must configure `server_side_encryption_configuration`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [311],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "s3", "encryption"],
}

findings contains finding if {
	some path, content in input.file_contents
	util.is_tf(path)
	some block in util.resource_blocks(content, "aws_s3_bucket")
	not contains(block, "server_side_encryption_configuration")
	bucket_name := util.resource_name(block)
	not _has_separate_sse_resource(content, bucket_name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no server_side_encryption_configuration.", [bucket_name]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": bucket_name,
	}
}

_has_separate_sse_resource(content, bucket_name) if {
	some block in util.resource_blocks(content, "aws_s3_bucket_server_side_encryption_configuration")
	regex.match(sprintf(`aws_s3_bucket\.%s(\.|\b)`, [bucket_name]), block)
}
