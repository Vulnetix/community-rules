# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_info_description

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0002",
	"name": "OpenAPI info.description must be non-empty",
	"description": "Spectral `info-description`: info.description must be a non-empty string.",
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
	description := object.get(spec.doc, ["info", "description"], null)
	_invalid(description)
	finding := {
		"rule_id": metadata.id,
		"message": "info.description must be a non-empty string.",
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": "info.description",
	}
}

_invalid(v) if not is_string(v)

_invalid(v) if v == ""
