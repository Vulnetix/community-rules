# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.rally_docker_approved_registry

import rego.v1

import data.vulnetix.rallyhealth.docker_utils
import data.vulnetix.rallyhealth.util

metadata := {
	"id": "CTNRSEC-0001",
	"name": "Dockerfiles must pull from an approved private registry",
	"description": "Each FROM image must be prefixed by one of an approved list of private registries (fork and tailor `_approved_private_registries`).",
	"help_uri": "",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [1104],
	"capec": [],
	"attack_technique": ["T1195"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "container", "supply-chain"],
}

_approved_private_registries := [
	"my.private.registry",
	"other.private.registry",
]

findings contains finding if {
	some path, content in input.file_contents
	docker_utils.is_dockerfile(path)
	stages := docker_utils.stage_names(content)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := docker_utils.strip_comment(line)
	startswith(lower(code), "from ")
	rest := trim_space(substring(code, 5, -1))
	tokens := split(rest, " ")
	count(tokens) > 0
	image := tokens[0]
	not startswith(image, "$")
	image != "scratch"
	not _starts_with_stage(image, stages)
	not util.item_startswith_in_list(image, _approved_private_registries)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Image %q does not pull from an approved private registry. Allowed: %v", [image, _approved_private_registries]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": i + 1,
		"snippet": line,
	}
}

_starts_with_stage(image, stages) if {
	some stage in stages
	startswith(image, stage)
}
