# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_s3_private

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0010",
	"name": "S3 buckets must not set ACL to public",
	"description": "`aws_s3_bucket.acl = \"public\"` (either spelling) exposes bucket contents to the public internet.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket#acl",
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
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_s3_bucket")
	acl := tf.string_attr(block, "acl")
	acl == "public"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q has ACL set to public.", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": tf.resource_name(block),
	}
}
