# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_fd_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-FD-02",
	"name": "Front Door frontend endpoints must attach a WAF policy",
	"description": "azurerm_frontdoor frontend_endpoint must set web_application_firewall_policy_link_id.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/front-door",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "front-door", "waf"],
}

findings contains finding if {
	some r in tf.resources("azurerm_frontdoor")
	not _has_waf(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Front Door %q has no frontend_endpoint with web_application_firewall_policy_link_id.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_waf(block) if {
	some ep in tf.sub_blocks(block, "frontend_endpoint")
	tf.has_key(ep, "web_application_firewall_policy_link_id")
}
