# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_elb_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-ELB-02",
	"name": "ALB listeners must use HTTPS with a recommended SSL policy",
	"description": "aws_lb_listener on application load balancers must set protocol = HTTPS, provide a certificate_arn, and use an approved ssl_policy.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/load-balancer",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-326"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elb", "tls"],
}

_allowed_policies := {
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
	"ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-FS-2018-06",
	"ELBSecurityPolicy-FS-1-1-2019-08",
	"ELBSecurityPolicy-FS-1-2-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-2015-05",
}

findings contains finding if {
	some r in tf.resources("aws_lb_listener")
	not _is_properly_configured(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ALB listener %q has an invalid HTTPS/SSL configuration.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

# Accept NLBs (protocol TCP/UDP/TLS is handled elsewhere).
_is_properly_configured(block) if {
	p := tf.string_attr(block, "protocol")
	p == "TCP"
}

_is_properly_configured(block) if {
	p := tf.string_attr(block, "protocol")
	p == "UDP"
}

_is_properly_configured(block) if {
	tf.string_attr(block, "protocol") == "HTTPS"
	tf.has_key(block, "certificate_arn")
	policy := tf.string_attr(block, "ssl_policy")
	_allowed_policies[policy]
}
