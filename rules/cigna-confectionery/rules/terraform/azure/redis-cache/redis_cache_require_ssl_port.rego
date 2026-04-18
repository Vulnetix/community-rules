# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_redis_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-REDIS-01",
	"name": "Redis Cache must disable the non-SSL port",
	"description": "azurerm_redis_cache must set enable_non_ssl_port = false.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/redis-cache",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "redis", "ssl"],
}

findings contains finding if {
	some r in tf.resources("azurerm_redis_cache")
	tf.is_not_false(r.block, "enable_non_ssl_port")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis Cache %q does not set enable_non_ssl_port = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
