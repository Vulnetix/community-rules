# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_openapi_tags_uniqueness

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0007",
	"name": "OpenAPI tag names must be unique",
	"description": "Spectral `openapi-tags-uniqueness`: each entry of `tags` must have a unique `name`.",
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
	tags := object.get(spec.doc, "tags", [])
	is_array(tags)
	some i, tag in tags
	is_object(tag)
	is_string(tag.name)
	dup_count := count([j | some j, t in tags; is_object(t); t.name == tag.name])
	dup_count > 1
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("tags[%d] duplicates name %q.", [i, tag.name]),
		"artifact_uri": spec.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": tag.name,
	}
}
