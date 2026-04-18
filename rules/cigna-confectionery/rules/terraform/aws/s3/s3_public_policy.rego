# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_s3_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-S3-03",
	"name": "S3 bucket policies must not grant wildcard principals without conditions",
	"description": "aws_s3_bucket_policy must not have Effect=Allow with Principal=\"*\" unless a Condition limits access (e.g. aws:SourceVpc or aws:PrincipalOrgID).",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/s3",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3"],
}

findings contains finding if {
	some r in tf.resources("aws_s3_bucket_policy")
	tf.has_wildcard_principal_without_condition(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket policy %q allows Principal=\"*\" without a limiting Condition.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
