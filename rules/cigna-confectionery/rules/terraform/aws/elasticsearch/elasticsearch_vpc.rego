# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_es_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-ES-01",
	"name": "Elasticsearch domains must deploy into a VPC",
	"description": "aws_elasticsearch_domain must declare a vpc_options block.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/elasticsearch",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elasticsearch", "network"],
}

findings contains finding if {
	some r in tf.resources("aws_elasticsearch_domain")
	not tf.has_sub_block(r.block, "vpc_options")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Elasticsearch domain %q is not deployed inside a VPC.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
