# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_ct_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-CT-01",
	"name": "CloudTrail trails must not be created in application accounts",
	"description": "Upstream policy rejects any aws_cloudtrail declaration (trails are managed centrally).",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/cloudtrail",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudtrail"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudtrail")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_cloudtrail resource %q should not be declared at the application layer.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
