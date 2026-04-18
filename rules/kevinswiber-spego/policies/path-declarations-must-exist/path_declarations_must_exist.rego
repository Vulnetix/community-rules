# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_path_declarations_must_exist

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0018",
	"name": "OpenAPI path parameters must not be empty",
	"description": "Spectral `path-declarations-must-exist`: paths must not contain empty parameter declarations (`{}`).",
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
	paths := object.get(spec.doc, "paths", {})
	is_object(paths)
	some p, _ in paths
	contains(p, "{}")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("path %q contains an empty {} parameter declaration.", [p]),
		"artifact_uri": spec.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": p,
	}
}
