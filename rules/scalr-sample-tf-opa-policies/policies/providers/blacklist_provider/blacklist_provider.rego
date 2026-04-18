# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_blacklist_provider

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-PROV-0001",
	"name": "Denied Terraform providers must not be declared",
	"description": "`provider \"<name>\" { ... }` must not reference any entry in `_blacklist`.",
	"help_uri": "",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "providers"],
}

_blacklist := {"azurerm"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	matches := regex.find_n(`provider\s+"([^"]+)"`, content, -1)
	some m in matches
	caps := regex.find_n(`"([^"]+)"`, m, 1)
	count(caps) > 0
	name := trim(caps[0], `"`)
	_blacklist[name]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Provider %q is not allowed.", [name]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": m,
	}
}
