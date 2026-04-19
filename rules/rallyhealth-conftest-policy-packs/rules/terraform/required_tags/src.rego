# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.rally_required_tags

import rego.v1

import data.vulnetix.rallyhealth.util

metadata := {
	"id": "AWSSEC-0005",
	"name": "AWS resources must carry required organizational tags",
	"description": "Resources that declare a `tags` block must include every key in `_minimum_required_tags`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/resource-tagging",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "tagging", "governance"],
}

_minimum_required_tags := [
	"owner",
	"environment",
	"application",
	"costCenter",
]

findings contains finding if {
	some path, content in input.file_contents
	util.is_tf(path)
	blocks := regex.find_n(`(?s)resource\s+"[^"]+"\s+"[^"]+"\s*\{(?:[^{}]|\{[^{}]*\})*?\}`, content, -1)
	some block in blocks
	_has_tags_block(block)
	missing := _missing_required(block)
	count(missing) > 0
	header := regex.find_n(`resource\s+"[^"]+"\s+"[^"]+"`, block, 1)
	count(header) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is missing required tag(s): %v.", [header[0], missing]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": header[0],
	}
}

_has_tags_block(block) if {
	regex.match(`(?s)tags\s*=?\s*\{`, block)
}

_missing_required(block) := missing if {
	missing := [tag |
		some tag in _minimum_required_tags
		not regex.match(sprintf(`(?m)"?%s"?\s*[:=]`, [tag]), block)
	]
}
