# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.ricardo_oci_storage_versioning

import rego.v1

import data.vulnetix.ricardosnyk.relations

metadata := {
	"id": "RICARDO-OCI-VER-001",
	"name": "OCI object storage bucket must have versioning enabled",
	"description": "`oci_objectstorage_bucket` should declare `versioning = \"Enabled\"`.",
	"help_uri": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingversioning.htm",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [1263],
	"capec": [],
	"attack_technique": ["T1485"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["oci", "object-storage", "versioning"],
}

findings contains finding if {
	some path, content in input.file_contents
	relations.is_tf(path)
	some block in relations.resource_blocks(content, "oci_objectstorage_bucket")
	not regex.match(`versioning\s*=\s*"Enabled"`, block)
	offset := indexof(content, block)
	name := relations.resource_name(block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("oci_objectstorage_bucket %q does not set versioning = \"Enabled\".", [name]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": relations.line_of(content, offset),
		"snippet": sprintf("oci_objectstorage_bucket %q", [name]),
	}
}
