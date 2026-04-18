# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_vpc_lambda_missing_eni_policy

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-LAMBDA-0002",
	"name": "VPC Lambdas must attach AWSLambdaVPCAccessExecutionRole",
	"description": "An `aws_lambda_function` with a `vpc_config` block needs an `aws_iam_role_policy_attachment` granting `AWSLambdaVPCAccessExecutionRole` (ENI create/delete permissions).",
	"help_uri": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "lambda", "vpc"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_lambda_function")
	tf.has_sub_block(block, "vpc_config")
	role_ref := _role_reference(block)
	not _has_vpc_policy_attachment(content, role_ref)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_lambda_function %q attaches to a VPC but role %q lacks AWSLambdaVPCAccessExecutionRole.", [tf.resource_name(block), role_ref]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": tf.resource_name(block),
	}
}

_role_reference(block) := ref if {
	matches := regex.find_n(`role\s*=\s*aws_iam_role\.([A-Za-z0-9_-]+)\.`, block, 1)
	count(matches) > 0
	caps := regex.find_n(`aws_iam_role\.([A-Za-z0-9_-]+)\.`, matches[0], 1)
	count(caps) > 0
	ref := trim_prefix(trim_suffix(caps[0], "."), "aws_iam_role.")
}

_has_vpc_policy_attachment(content, role_ref) if {
	some block in tf.resource_blocks(content, "aws_iam_role_policy_attachment")
	regex.match(`policy_arn\s*=\s*"arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"`, block)
	regex.match(sprintf(`role\s*=\s*aws_iam_role\.%s\.`, [role_ref]), block)
}
