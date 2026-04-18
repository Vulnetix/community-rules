# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_sa_04

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-SA-04",
	"name": "Storage accounts must require TLS 1.2",
	"description": "azurerm_storage_account must set min_tls_version = \"TLS1_2\".",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/storage-account",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "storage-account", "tls"],
}

findings contains finding if {
	some r in tf.resources("azurerm_storage_account")
	not tf.string_attr(r.block, "min_tls_version") == "TLS1_2"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q does not set min_tls_version = TLS1_2.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
