# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_tag_description

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0008",
	"name": "OpenAPI tags must include descriptions",
	"description": "Spectral `tag-description`: each tag entry must have a description.",
	"help_uri": "https://github.com/kevinswiber/spego",
	"languages": ["openapi", "yaml", "json"],
	"severity": "low",
	"level": "note",
	"kind": "api",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["openapi", "documentation"],
}

findings contains finding if {
	some spec in openapi.specs
	tags := object.get(spec.doc, "tags", [])
	is_array(tags)
	some i, tag in tags
	is_object(tag)
	not is_string(tag.description)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("tags[%d] (%v) has no description.", [i, object.get(tag, "name", "")]),
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": object.get(tag, "name", ""),
	}
}
