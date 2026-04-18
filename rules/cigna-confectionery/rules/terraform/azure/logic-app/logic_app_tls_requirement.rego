# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_logic_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-LOGIC-02",
	"name": "Logic Apps must use TLS 1.2 or higher",
	"description": "azurerm_logic_app_standard site_config.min_tls_version must be >= 1.2.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/logic-app",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-327"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "logic-app", "tls"],
}

findings contains finding if {
	some r in tf.resources("azurerm_logic_app_standard")
	not _has_required_tls(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Logic App %q does not set site_config.min_tls_version >= 1.2.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_required_tls(block) if {
	some sc in tf.sub_blocks(block, "site_config")
	v := tf.string_attr(sc, "min_tls_version")
	to_number(v) >= 1.2
}
