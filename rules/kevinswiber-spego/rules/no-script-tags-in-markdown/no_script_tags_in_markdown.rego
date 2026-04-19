# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_no_script_tags_in_markdown

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0023",
	"name": "OpenAPI markdown must not contain <script> tags",
	"description": "Spectral `no-script-tags-in-markdown`: title/description fields must not contain `<script`.",
	"help_uri": "https://github.com/kevinswiber/spego",
	"languages": ["openapi", "yaml", "json"],
	"severity": "high",
	"level": "error",
	"kind": "api",
	"cwe": ["CWE-79"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["openapi", "security", "xss"],
}

findings contains finding if {
	some spec in openapi.specs
	walk(spec.doc, [path, value])
	some key in ["title", "description"]
	v := value[key]
	is_string(v)
	contains(lower(v), "<script")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%q contains `<script` in %s.", [openapi.join_path(array.concat(path, [key])), spec.path]),
		"artifact_uri": spec.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": v,
	}
}
