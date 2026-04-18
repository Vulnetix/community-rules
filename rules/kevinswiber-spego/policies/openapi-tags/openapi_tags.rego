# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_openapi_tags

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0006",
	"name": "OpenAPI document must declare a non-empty tags array",
	"description": "Spectral `openapi-tags`: top-level `tags` must be a non-empty array.",
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
	tags := object.get(spec.doc, "tags", null)
	_invalid(tags)
	finding := {
		"rule_id": metadata.id,
		"message": "tags must be a non-empty array at the document root.",
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": "tags",
	}
}

_invalid(v) if is_null(v)

_invalid(v) if not is_array(v)

_invalid(v) if {
	is_array(v)
	count(v) == 0
}
