# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.ricardo_gcp_function_runtime

import rego.v1

import data.vulnetix.ricardosnyk.relations
import data.vulnetix.ricardosnyk.gcp_deprecated_runtimes as runtimes

metadata := {
	"id": "RICARDO-GCP-FN-001",
	"name": "GCP cloud function uses a deprecated runtime",
	"description": "`google_cloudfunctions_function` must not declare a deprecated `runtime` (e.g., nodejs6, nodejs8, go111).",
	"help_uri": "https://cloud.google.com/functions/docs/runtime-support",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [1104],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["gcp", "cloud-functions", "runtime", "terraform"],
}

findings contains finding if {
	some path, content in input.file_contents
	relations.is_tf(path)
	some block in relations.resource_blocks(content, "google_cloudfunctions_function")
	runtime_match := regex.find_n(`runtime\s*=\s*"([^"]+)"`, block, 1)
	count(runtime_match) > 0
	rt := regex.replace(runtime_match[0], `.*"([^"]+)".*`, "$1")
	runtimes.dep_runtimes[rt]
	offset := indexof(content, block)
	name := relations.resource_name(block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_cloudfunctions_function %q uses deprecated runtime %q.", [name, rt]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": relations.line_of(content, offset),
		"snippet": runtime_match[0],
	}
}
