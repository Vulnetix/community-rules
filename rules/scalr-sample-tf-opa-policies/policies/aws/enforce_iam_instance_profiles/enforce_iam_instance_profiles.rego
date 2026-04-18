# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_iam_instance_profiles

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0004",
	"name": "EC2 iam_instance_profile must be in allow-list",
	"description": "When an `aws_instance` declares an `iam_instance_profile`, the profile name must appear in `_allowed_iam_profiles` (fork and tailor).",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#iam_instance_profile",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ec2", "iam"],
}

_allowed_iam_profiles := {
	"my_iam_profile",
	"my_iam_profile_2",
	"my_iam_profile_3",
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_instance")
	profile := tf.string_attr(block, "iam_instance_profile")
	not _allowed_iam_profiles[profile]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_instance %q uses iam_instance_profile %q which is not in the allow-list.", [tf.resource_name(block), profile]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": profile,
	}
}
