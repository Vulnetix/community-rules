# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.rally_docker_sensitive_env_args

import rego.v1

import data.vulnetix.rallyhealth.docker_utils

metadata := {
	"id": "CTNRSEC-0002",
	"name": "Dockerfiles must not use ENV/ARG for sensitive values",
	"description": "ENV/ARG statements whose key contains secret-looking substrings bake secrets into image layers (recoverable via `docker history`).",
	"help_uri": "https://docs.docker.com/develop/develop-images/build_enhancements/#new-docker-build-secret-information",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [522, 798],
	"capec": [],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "container", "secrets"],
}

_sensitive_env_keys := [
	"secret",
	"apikey",
	"token",
	"passwd",
	"password",
	"pwd",
	"api_key",
	"credential",
]

# Substrings commonly seen in env keys that match sensitive patterns but are
# not themselves secrets (e.g. a vendor name containing "pwd").
_excepted_substrings := [
	"amplitude",
]

findings contains finding if {
	some path, content in input.file_contents
	docker_utils.is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := docker_utils.strip_comment(line)
	lc := lower(code)
	some prefix in ["env ", "arg "]
	startswith(lc, prefix)
	rest := trim_space(substring(code, count(prefix), -1))
	key := _key_of(rest)
	lkey := lower(key)
	some sensitive in _sensitive_env_keys
	contains(lkey, sensitive)
	not _is_excepted(lkey)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s key %q suggests a sensitive value stored in a Docker image layer; use BuildKit --secret or a multi-stage build.", [upper(trim_space(prefix)), key]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": i + 1,
		"snippet": line,
	}
}

_key_of(rest) := key if {
	eq_idx := indexof(rest, "=")
	eq_idx >= 0
	key := trim_space(substring(rest, 0, eq_idx))
} else := key if {
	sp_idx := indexof(rest, " ")
	sp_idx >= 0
	key := trim_space(substring(rest, 0, sp_idx))
} else := trim_space(rest)

_is_excepted(lkey) if {
	some s in _excepted_substrings
	contains(lkey, s)
}
