# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_eks_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-EKS-02",
	"name": "EKS clusters must use private endpoints",
	"description": "aws_eks_cluster.vpc_config must set endpoint_private_access = true and endpoint_public_access = false.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/eks",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "eks", "network"],
}

findings contains finding if {
	some r in tf.resources("aws_eks_cluster")
	not _private_only(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EKS cluster %q exposes a public API endpoint.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_private_only(block) if {
	some sb in tf.sub_blocks(block, "vpc_config")
	tf.bool_attr(sb, "endpoint_private_access") == true
	tf.bool_attr(sb, "endpoint_public_access") == false
}
