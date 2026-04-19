# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_license_url

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0004",
	"name": "OpenAPI license must include a URL",
	"description": "Spectral `license-url`: info.license.url must be a non-empty string.",
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
	url := object.get(spec.doc, ["info", "license", "url"], null)
	_invalid(url)
	finding := {
		"rule_id": metadata.id,
		"message": "info.license.url must be a non-empty string.",
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": "info.license.url",
	}
}

_invalid(v) if not is_string(v)

_invalid(v) if v == ""
