# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_required_tags

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-MGMT-0006",
	"name": "Resources must declare required organizational tags/labels",
	"description": "Any resource block whose provider uses `tags` (AWS, Azure) or `labels` (GCP) must declare every key in `_required_tags`.",
	"help_uri": "",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "tagging", "governance"],
}

_required_tags := ["owner", "department"]

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)resource\s+"[^"]+"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, content, -1)
	some block in blocks
	_declares_tags(block)
	missing := _missing(block)
	count(missing) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is missing required tag(s)/label(s): %v.", [tf.resource_address(block), missing]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": tf.resource_address(block),
	}
}

_declares_tags(block) if regex.match(`(?s)\btags\s*=\s*\{`, block)

_declares_tags(block) if regex.match(`(?s)\blabels\s*=\s*\{`, block)

_missing(block) := missing if {
	missing := [tag |
		some tag in _required_tags
		not regex.match(sprintf(`(?m)"?%s"?\s*[:=]`, [tag]), block)
	]
}
