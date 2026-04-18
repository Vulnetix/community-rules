# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_duplicated_entry_in_enum

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0024",
	"name": "OpenAPI enum values must be unique",
	"description": "Spectral `duplicated-entry-in-enum`: `enum` arrays must not contain duplicate entries.",
	"help_uri": "https://github.com/kevinswiber/spego",
	"languages": ["openapi", "yaml", "json"],
	"severity": "medium",
	"level": "warning",
	"kind": "api",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["openapi", "governance"],
}

findings contains finding if {
	some spec in openapi.specs
	walk(spec.doc, [path, value])
	is_object(value)
	enum := value.enum
	is_array(enum)
	some i1, v1 in enum
	some i2, v2 in enum
	i1 < i2
	v1 == v2
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("enum at %s has duplicate value %v.", [openapi.join_path(array.concat(path, ["enum"])), v1]),
		"artifact_uri": spec.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%v", [v1]),
	}
}
