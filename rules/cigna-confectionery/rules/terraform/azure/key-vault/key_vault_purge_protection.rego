# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_kv_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-KV-01",
	"name": "Key Vaults must enable purge protection",
	"description": "azurerm_key_vault must set purge_protection_enabled = true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/key-vault",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-320"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "key-vault"],
}

findings contains finding if {
	some r in tf.resources("azurerm_key_vault")
	tf.is_not_true(r.block, "purge_protection_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q does not set purge_protection_enabled = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
