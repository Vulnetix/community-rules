# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_ec2_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-EC2-01",
	"name": "EC2 instances must have an IAM instance profile",
	"description": "aws_instance must set iam_instance_profile so SSM and CloudWatch agents can authenticate.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/ec2",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ec2", "iam"],
}

findings contains finding if {
	some r in tf.resources("aws_instance")
	not tf.has_key(r.block, "iam_instance_profile")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EC2 instance %q has no iam_instance_profile.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
