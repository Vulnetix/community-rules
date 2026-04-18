# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_aws_resource

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0001",
	"name": "Only allow-listed Terraform resource types may be declared",
	"description": "Resources must match one of `_allowed_resources`; fork and tailor the list to your fleet.",
	"help_uri": "",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "governance"],
}

_allowed_resources := {
	"aws_security_group",
	"aws_instance",
	"aws_s3_bucket",
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)resource\s+"([^"]+)"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, content, -1)
	some block in blocks
	t := tf.resource_type(block)
	not _allowed_resources[t]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Resource type %q is not in the allow-list.", [t]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": tf.resource_address(block),
	}
}
