# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_operation_tag_defined

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0016",
	"name": "OpenAPI operation tags must be declared globally",
	"description": "Spectral `operation-tag-defined`: operation tags must each appear in the document's top-level tags.",
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
	tags := object.get(spec.doc, "tags", [])
	is_array(tags)
	global := {t.name |
		some t in tags
		is_object(t)
		is_string(t.name)
	}
	paths := object.get(spec.doc, "paths", {})
	is_object(paths)
	some p, path_item in paths
	is_object(path_item)
	some method, op in path_item
	openapi.is_method_valid(method)
	is_object(op)
	op_tags := object.get(op, "tags", [])
	is_array(op_tags)
	some i, tag in op_tags
	is_string(tag)
	not global[tag]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s.tags[%d] (%q) is not declared in the document's top-level tags.", [p, method, i, tag]),
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": tag,
	}
}
