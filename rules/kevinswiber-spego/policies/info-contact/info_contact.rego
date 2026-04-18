# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_info_contact

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0001",
	"name": "OpenAPI info must include a contact object",
	"description": "Spectral `info-contact`: every OpenAPI document must expose an `info.contact` object.",
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
	"tags": ["openapi", "documentation", "governance"],
}

findings contains finding if {
	some spec in openapi.specs
	not is_object(object.get(spec.doc, ["info", "contact"], null))
	finding := {
		"rule_id": metadata.id,
		"message": "info.contact must be an object.",
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": "info.contact",
	}
}
