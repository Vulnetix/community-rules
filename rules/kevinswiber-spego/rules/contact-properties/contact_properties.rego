# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_contact_properties

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0005",
	"name": "OpenAPI contact must include name, url, and email",
	"description": "Spectral `contact-properties`: info.contact must populate name, url, and email.",
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
	contact := object.get(spec.doc, ["info", "contact"], null)
	is_object(contact)
	required := {"name", "email", "url"}
	present := {k | some k in required; is_string(contact[k]); contact[k] != ""}
	count(present) < count(required)
	missing := required - present
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("info.contact is missing required keys: %v.", [sort(missing)]),
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": "info.contact",
	}
}
