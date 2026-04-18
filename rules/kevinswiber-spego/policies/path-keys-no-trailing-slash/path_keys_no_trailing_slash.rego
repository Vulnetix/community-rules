# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_path_keys_no_trailing_slash

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0019",
	"name": "OpenAPI paths must not end with a trailing slash",
	"description": "Spectral `path-keys-no-trailing-slash`: path keys must not end with `/`.",
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
	paths := object.get(spec.doc, "paths", {})
	is_object(paths)
	some p, _ in paths
	endswith(p, "/")
	p != "/"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("path %q has a trailing slash.", [p]),
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": p,
	}
}
