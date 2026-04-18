# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_sm_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-SM-03",
	"name": "SageMaker notebook instances must disable direct internet access",
	"description": "aws_sagemaker_notebook_instance must not set direct_internet_access = Enabled.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/sagemaker",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sagemaker", "network"],
}

findings contains finding if {
	some r in tf.resources("aws_sagemaker_notebook_instance")
	tf.string_attr(r.block, "direct_internet_access") == "Enabled"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SageMaker notebook %q has direct_internet_access=Enabled.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
