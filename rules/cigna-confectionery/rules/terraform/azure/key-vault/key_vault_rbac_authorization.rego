# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_kv_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-KV-02",
	"name": "Key Vaults must enable RBAC authorization",
	"description": "azurerm_key_vault must set enable_rbac_authorization = true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/key-vault",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "key-vault", "rbac"],
}

findings contains finding if {
	some r in tf.resources("azurerm_key_vault")
	tf.is_not_true(r.block, "enable_rbac_authorization")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q does not set enable_rbac_authorization = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
