# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_docker_latest_tag

import rego.v1

import data.vulnetix.embark.docker

metadata := {
	"id": "EMBARK-DOCKER-03",
	"name": "Dockerfile FROM must pin an explicit non-latest tag",
	"description": "DOCKER_03: FROM must not use :latest.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/DOCKER_03",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "container",
	"cwe": ["CWE-1357"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "supply-chain"],
}

findings contains finding if {
	some path, content in input.file_contents
	docker.is_dockerfile_path(path)
	some from in docker.froms(content)
	parts := split(from, ":")
	count(parts) >= 2
	lower(parts[1]) == "latest"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("FROM %q uses the :latest tag.", [from]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("FROM %s", [from]),
	}
}
