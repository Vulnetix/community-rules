# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_cog_04

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-COG-04",
	"name": "Cognitive Services must set network_acls default_action = Deny",
	"description": "azurerm_cognitive_account must have a network_acls block with default_action = \"Deny\".",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/cognitive-services",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "cognitive-services", "network"],
}

findings contains finding if {
	some r in tf.resources("azurerm_cognitive_account")
	not _has_deny_default(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cognitive account %q has no network_acls.default_action = Deny.", [r.name]),
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
