# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_sa_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-SA-01",
	"name": "Storage accounts must disable public blob access",
	"description": "azurerm_storage_account must set allow_blob_public_access = false.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/storage-account",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "storage-account"],
}

findings contains finding if {
	some r in tf.resources("azurerm_storage_account")
	tf.is_not_false(r.block, "allow_blob_public_access")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q does not set allow_blob_public_access = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
