# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_elb_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-ELB-03",
	"name": "Classic ELB policies must not enable deprecated SSL/TLS protocols",
	"description": "aws_load_balancer_policy policy_attributes must not enable Protocol-TLSv1, Protocol-SSLv3/SSLv2/SSLv1.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/load-balancer",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elb", "tls"],
}

_disallowed := {"Protocol-TLSv1", "Protocol-SSLv3", "Protocol-SSLv2", "Protocol-SSLv1"}

findings contains finding if {
	some r in tf.resources("aws_load_balancer_policy")
	some pa in tf.sub_blocks(r.block, "policy_attribute")
	n := tf.string_attr(pa, "name")
	_disallowed[n]
	tf.string_attr(pa, "value") == "true"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Classic ELB policy %q enables deprecated protocol %q.", [r.name, n]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
