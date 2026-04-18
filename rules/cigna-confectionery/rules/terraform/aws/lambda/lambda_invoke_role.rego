# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_lambda_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-LAMBDA-01",
	"name": "Lambda functions must not reference a role that grants lambda:InvokeLambda",
	"description": "Detects aws_lambda_function referencing an aws_iam_role whose assume_role_policy allows lambda.amazonaws.com to call lambda:InvokeLambda.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/lambda",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "lambda", "iam"],
}

findings contains finding if {
	some fn in tf.resources("aws_lambda_function")
	role_ref := tf.string_attr(fn.block, "role")
	some role in tf.resources("aws_iam_role")
	contains(role_ref, role.name)
	_is_invoke_policy(role.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Lambda function %q uses role %q which allows lambda:InvokeLambda.", [fn.name, role.name]),
		"artifact_uri": fn.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [fn.type, fn.name]),
	}
}

_is_invoke_policy(block) if {
	regex.match(`"Service"\s*:\s*"lambda\.amazonaws\.com"`, block)
	regex.match(`"Action"\s*:\s*"lambda:InvokeLambda"`, block)
}

_is_invoke_policy(block) if {
	regex.match(`Service\s*=\s*"lambda\.amazonaws\.com"`, block)
	regex.match(`Action\s*=\s*"lambda:InvokeLambda"`, block)
}
