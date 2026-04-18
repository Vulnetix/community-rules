# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_fd_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-FD-01",
	"name": "Front Door must require HTTPS or redirect HTTP to HTTPS",
	"description": "azurerm_frontdoor routing_rule must either accept HTTPS only with forwarding_configuration.forwarding_protocol = HttpsOnly, or redirect HTTP via redirect_configuration.redirect_protocol = HttpsOnly.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/front-door",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "front-door", "https"],
}

findings contains finding if {
	some r in tf.resources("azurerm_frontdoor")
	not _has_valid_rule(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Front Door %q does not enforce HTTPS (or HTTP→HTTPS redirect).", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_valid_rule(block) if {
	some rule in tf.sub_blocks(block, "routing_rule")
	_https_only(rule)
}

_has_valid_rule(block) if {
	some rule in tf.sub_blocks(block, "routing_rule")
	_redirects_http(rule)
}

_https_only(rule) if {
	some fwd in tf.sub_blocks(rule, "forwarding_configuration")
	tf.string_attr(fwd, "forwarding_protocol") == "HttpsOnly"
}

_redirects_http(rule) if {
	some red in tf.sub_blocks(rule, "redirect_configuration")
	tf.string_attr(red, "redirect_protocol") == "HttpsOnly"
}
