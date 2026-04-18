# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_sa_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-SA-03",
	"name": "Storage accounts must not explicitly allow public blob access",
	"description": "azurerm_storage_account must not set allow_blob_public_access = true.",
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
	tf.bool_attr(r.block, "allow_blob_public_access") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage account %q sets allow_blob_public_access = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
