# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_docker_sudo_usage

import rego.v1

import data.vulnetix.embark.docker

metadata := {
	"id": "EMBARK-DOCKER-04",
	"name": "Dockerfile RUN must not invoke sudo",
	"description": "DOCKER_04: RUN commands must not use sudo.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/DOCKER_04",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "container",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "security"],
}

findings contains finding if {
	some path, content in input.file_contents
	docker.is_dockerfile_path(path)
	some run in docker.runs(content)
	regex.match(`(^|\s)sudo(\s|$)`, lower(run))
	finding := {
		"rule_id": metadata.id,
		"message": "RUN uses sudo.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("RUN %s", [run]),
	}
}
