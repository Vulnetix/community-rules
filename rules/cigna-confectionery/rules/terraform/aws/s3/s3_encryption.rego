# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_s3_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-S3-01",
	"name": "S3 buckets must configure server-side encryption with AES256 or aws:kms",
	"description": "aws_s3_bucket must declare server_side_encryption_configuration with sse_algorithm of AES256 or aws:kms.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/s3",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_s3_bucket")
	not _has_valid_sse(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket %q is missing server_side_encryption_configuration with AES256 or aws:kms.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_valid_sse(block) if {
	some outer in tf.sub_blocks(block, "server_side_encryption_configuration")
	regex.match(`sse_algorithm\s*=\s*"(AES256|aws:kms)"`, outer)
}
