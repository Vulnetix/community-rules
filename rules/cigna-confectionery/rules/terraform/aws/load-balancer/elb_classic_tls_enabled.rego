# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_elb_04

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-ELB-04",
	"name": "Classic ELBs must have TLS (HTTPS listener + certificate) enabled",
	"description": "aws_elb must declare at least one listener with lb_protocol = https and a ssl_certificate_id ARN.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/load-balancer",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elb", "tls"],
}

findings contains finding if {
	some r in tf.resources("aws_elb")
	not _tls_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Classic ELB %q does not enable TLS (HTTPS listener with SSL certificate).", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_tls_enabled(block) if {
	some sb in tf.sub_blocks(block, "listener")
	lower(tf.string_attr(sb, "lb_protocol")) == "https"
	cert := tf.string_attr(sb, "ssl_certificate_id")
	contains(cert, "arn")
}
