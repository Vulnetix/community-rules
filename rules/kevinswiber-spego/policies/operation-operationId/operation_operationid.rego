# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_operation_operationid

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0010",
	"name": "OpenAPI operations must declare an operationId",
	"description": "Spectral `operation-operationId`: every operation must have a non-empty operationId.",
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
	"tags": ["openapi", "documentation"],
}

findings contains finding if {
	some spec in openapi.specs
	paths := object.get(spec.doc, "paths", {})
	is_object(paths)
	some p, path_item in paths
	is_object(path_item)
	some method, op in path_item
	openapi.is_method_valid(method)
	is_object(op)
	_invalid(op)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s.operationId must be a non-empty string.", [p, method]),
		"artifact_uri": spec.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}

_invalid(op) if not is_string(op.operationId)

_invalid(op) if op.operationId == ""
