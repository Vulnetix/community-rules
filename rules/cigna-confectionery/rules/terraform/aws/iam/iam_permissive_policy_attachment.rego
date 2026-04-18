# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_iam_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-IAM-03",
	"name": "IAM policy attachments must not use overly permissive AWS managed policies",
	"description": "Detects attachments of AdministratorAccess, IAMFullAccess, PowerUserAccess and similar managed policies.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/iam",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

_attach_types := {
	"aws_iam_policy_attachment",
	"aws_iam_user_policy_attachment",
	"aws_iam_group_policy_attachment",
	"aws_iam_role_policy_attachment",
}

_deny_policies := {
	"arn:aws:iam::aws:policy/AdministratorAccess",
	"arn:aws:iam::aws:policy/IAMFullAccess",
	"arn:aws:iam::aws:policy/AmazonS3FullAccess",
	"arn:aws:iam::aws:policy/AmazonElasticMapReduceFullAccess",
	"arn:aws:iam::aws:policy/PowerUserAccess",
	"arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM",
	"arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role",
	"arn:aws:iam::aws:policy/AWSLambdaFullAccess",
}

findings contains finding if {
	some t in _attach_types
	some r in tf.resources(t)
	arn := tf.string_attr(r.block, "policy_arn")
	_deny_policies[arn]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Attachment %q references overly permissive managed policy %q.", [r.name, arn]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
