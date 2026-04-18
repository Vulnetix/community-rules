# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_iam_06

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-IAM-06",
	"name": "Sensitive IAM actions must be scoped to specific resources",
	"description": "Detects high-risk actions (iam:PassRole, sts:AssumeRole, iam:CreateRole, s3 get/put, dynamodb get/query) combined with Resource=*.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/iam",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

_iam_types := {"aws_iam_policy", "aws_iam_group_policy", "aws_iam_role_policy", "aws_iam_user_policy"}

_sensitive := [
	"iam:PassRole",
	"sts:AssumeRole",
	"s3:PutObject",
	"s3:GetObject",
	"s3:Get\\*",
	"s3:Put\\*",
	"iam:CreatePolicy",
	"iam:CreatePolicyVersion",
	"iam:CreateRole",
	"iam:AttachRolePolicy",
	"dynamodb:GetItem",
	"dynamodb:Query",
]

findings contains finding if {
	some t in _iam_types
	some r in tf.resources(t)
	_has_sensitive_star(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q grants a sensitive action with Resource=*.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_sensitive_star(block) if {
	_has_resource_star(block)
	some a in _sensitive
	regex.match(sprintf(`"%s"`, [a]), block)
}

_has_sensitive_star(block) if {
	_has_resource_star(block)
	some a in _sensitive
	regex.match(sprintf(`= *"%s"`, [a]), block)
}

_has_resource_star(block) if regex.match(`"Resource"\s*:\s*"\*"`, block)
_has_resource_star(block) if regex.match(`Resource\s*=\s*"\*"`, block)
