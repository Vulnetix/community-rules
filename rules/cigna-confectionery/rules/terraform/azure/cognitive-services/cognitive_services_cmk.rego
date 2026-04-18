# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_cog_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-COG-01",
	"name": "Cognitive Services must be encrypted with a customer-managed key",
	"description": "Each azurerm_cognitive_account must have a matching azurerm_cognitive_account_customer_managed_key.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/cognitive-services",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "cognitive-services", "encryption"],
}

findings contains finding if {
	some r in tf.resources("azurerm_cognitive_account")
	not _has_cmk(r.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cognitive account %q has no azurerm_cognitive_account_customer_managed_key.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_cmk(account_name) if {
	some cmk in tf.resources("azurerm_cognitive_account_customer_managed_key")
	regex.match(sprintf(`cognitive_account_id\s*=\s*azurerm_cognitive_account\.%s\.id\b`, [account_name]), cmk.block)
}
