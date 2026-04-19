# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_operation_operationid_valid_in_url

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0012",
	"name": "OpenAPI operationId must be URL-safe",
	"description": "Spectral `operation-operationId-valid-in-url`: operationId must only use characters valid in URLs.",
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
	"tags": ["openapi", "governance"],
}

_valid_re := `^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]*$`

findings contains finding if {
	some spec in openapi.specs
	paths := object.get(spec.doc, "paths", {})
	is_object(paths)
	some p, path_item in paths
	is_object(path_item)
	some method, op in path_item
	openapi.is_method_valid(method)
	is_object(op)
	is_string(op.operationId)
	op.operationId != ""
	not regex.match(_valid_re, op.operationId)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("operationId %q contains characters that are not URL-safe.", [op.operationId]),
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}
