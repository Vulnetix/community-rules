# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_redis_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-REDIS-03",
	"name": "Redis Cache must use TLS 1.2 or higher",
	"description": "azurerm_redis_cache minimum_tls_version must be >= 1.2.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/redis-cache",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "redis", "tls"],
}

findings contains finding if {
	some r in tf.resources("azurerm_redis_cache")
	not _has_required_tls(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis Cache %q does not set minimum_tls_version >= 1.2.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_required_tls(block) if {
	v := tf.string_attr(block, "minimum_tls_version")
	to_number(v) >= 1.2
}
