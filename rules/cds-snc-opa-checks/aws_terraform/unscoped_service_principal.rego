# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_unscoped_service_principal

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-IAM-0002",
	"name": "IAM service-principal policies must scope by AWS:SourceAccount",
	"description": "An `aws_iam_policy` whose statement grants a `Principal.Service` (other than `sts:AssumeRole`) must include an `AWS:SourceAccount` StringLike condition to prevent cross-account confused-deputy attacks.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [441],
	"capec": [],
	"attack_technique": ["T1078.004"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "iam", "confused-deputy"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_iam_policy")
	regex.match(`"Principal"\s*:\s*\{[^{}]*"Service"`, block)
	not regex.match(`"Action"\s*:\s*"sts:AssumeRole"`, block)
	not regex.match(`"AWS:SourceAccount"`, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_iam_policy %q grants a service principal but lacks an AWS:SourceAccount StringLike condition.", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": tf.resource_name(block),
	}
}
