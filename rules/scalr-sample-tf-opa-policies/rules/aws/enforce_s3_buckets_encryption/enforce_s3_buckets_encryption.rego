# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_s3_bucket_encryption

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0009",
	"name": "S3 buckets must restrict ACL and enforce server-side encryption",
	"description": "`aws_s3_bucket.acl` must be in `_allowed_acls`, and the bucket (or a matching `aws_s3_bucket_server_side_encryption_configuration`) must use an approved SSE algorithm.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [311, 284],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "s3", "encryption"],
}

_allowed_acls := {"private"}

_allowed_sse_algorithms := {"aws:kms", "AES256"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_s3_bucket")
	acl := tf.string_attr(block, "acl")
	not _allowed_acls[acl]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q ACL %q is not allowed.", [tf.resource_name(block), acl]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": acl,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_s3_bucket")
	bucket := tf.resource_name(block)
	not _has_sse(content, block, bucket)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has no server-side encryption configured.", [bucket]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": bucket,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_s3_bucket_server_side_encryption_configuration")
	algos := tf.string_attrs(block, "sse_algorithm")
	some algo in algos
	not _allowed_sse_algorithms[algo]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket_server_side_encryption_configuration %q uses unapproved sse_algorithm %q.", [tf.resource_name(block), algo]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": algo,
	}
}

_has_sse(_, block, _) if {
	contains(block, "server_side_encryption_configuration")
}

_has_sse(content, _, bucket) if {
	some sse_block in tf.resource_blocks(content, "aws_s3_bucket_server_side_encryption_configuration")
	regex.match(sprintf(`aws_s3_bucket\.%s(\.|\b)`, [bucket]), sse_block)
}
