# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_docker_curl_bashing

import rego.v1

import data.vulnetix.embark.docker

metadata := {
	"id": "EMBARK-DOCKER-06",
	"name": "Dockerfile RUN must not pipe remote scripts to a shell",
	"description": "DOCKER_06: curl/wget piped or redirected to a shell is a supply-chain risk.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/DOCKER_06",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "container",
	"cwe": ["CWE-494", "CWE-78"],
	"capec": ["CAPEC-184"],
	"attack_technique": ["T1608.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "supply-chain", "security"],
}

findings contains finding if {
	some path, content in input.file_contents
	docker.is_dockerfile_path(path)
	some run in docker.runs(content)
	regex.match(`(curl|wget).*[|>].*`, lower(run))
	finding := {
		"rule_id": metadata.id,
		"message": "RUN uses curl|sh / wget|sh style remote script execution.",
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("RUN %s", [run]),
	}
}
