# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_elb_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-ELB-01",
	"name": "Application load balancers must enable access logs",
	"description": "aws_lb of load_balancer_type \"application\" must declare an access_logs block.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/load-balancer",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elb", "logging"],
}

findings contains finding if {
	some r in tf.resources("aws_lb")
	_is_alb(r.block)
	not tf.has_sub_block(r.block, "access_logs")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Application load balancer %q does not configure access_logs.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_alb(block) if not tf.has_key(block, "load_balancer_type")
_is_alb(block) if tf.string_attr(block, "load_balancer_type") == "application"
