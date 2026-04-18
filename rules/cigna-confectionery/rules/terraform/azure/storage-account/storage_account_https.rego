# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_sa_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-SA-02",
	"name": "Storage accounts must enable HTTPS traffic only",
	"description": "azurerm_storage_account must set enable_https_traffic_only = true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/storage-account",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "storage-account", "https"],
}

findings contains finding if {
	some r in tf.resources("azurerm_storage_account")
	tf.is_not_true(r.block, "enable_https_traffic_only")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q does not set enable_https_traffic_only = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
