# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_kv_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-KV-03",
	"name": "Key Vaults must restrict network access",
	"description": "azurerm_key_vault network_acls block must set default_action = \"Deny\".",
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
	"tags": ["terraform", "azure", "key-vault", "network"],
}

findings contains finding if {
	some r in tf.resources("azurerm_key_vault")
	not _has_deny_default(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault %q has no network_acls.default_action = Deny.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_deny_default(block) if {
	some nb in tf.sub_blocks(block, "network_acls")
	tf.string_attr(nb, "default_action") == "Deny"
}
