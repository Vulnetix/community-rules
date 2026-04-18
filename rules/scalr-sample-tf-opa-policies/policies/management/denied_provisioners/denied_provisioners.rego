# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_denied_provisioners

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-MGMT-0001",
	"name": "Denied provisioner types must not be used",
	"description": "Resource blocks must not include a `provisioner \"<denied>\"` sub-block. Default denied list is `local-exec`.",
	"help_uri": "https://developer.hashicorp.com/terraform/language/v1.5.x/resources/provisioners/syntax",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [78],
	"capec": [],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "provisioner"],
}

_denied_provisioners := {"local-exec"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)resource\s+"[^"]+"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, content, -1)
	some block in blocks
	provisioner_decls := regex.find_n(`provisioner\s+"([^"]+)"`, block, -1)
	some decl in provisioner_decls
	caps := regex.find_n(`"([^"]+)"`, decl, 1)
	count(caps) > 0
	t := trim(caps[0], `"`)
	_denied_provisioners[t]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s uses denied provisioner %q.", [tf.resource_address(block), t]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": decl,
	}
}
