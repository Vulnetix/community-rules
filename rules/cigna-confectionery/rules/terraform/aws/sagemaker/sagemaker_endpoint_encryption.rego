# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_sm_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-SM-01",
	"name": "SageMaker endpoints must be encrypted with a KMS key",
	"description": "aws_sagemaker_endpoint_configuration must set kms_key_arn.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/sagemaker",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sagemaker", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_sagemaker_endpoint_configuration")
	not tf.has_key(r.block, "kms_key_arn")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SageMaker endpoint configuration %q has no kms_key_arn set.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
