# Adapted from https://github.com/hojjatsajjadinia/OPA-Security-Rules
# Original License: MIT (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.hojjat_docker_rules

import rego.v1

metadata := {
	"id": "HOJJAT-DF-001",
	"name": "Dockerfile hardening (expose/chown/secrets)",
	"description": "Dockerfile hardening: non-root ownership, no exposed SSH/RDP, no secrets in ENV, no `:latest` tag, no curl/wget, no package upgrades.",
	"help_uri": "https://github.com/hojjatsajjadinia/OPA-Security-Rules",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [250, 276, 732, 798],
	"capec": ["CAPEC-507"],
	"attack_technique": ["T1610"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "container", "hardening"],
}

_is_dockerfile(path) if endswith(lower(path), "/dockerfile")

_is_dockerfile(path) if lower(path) == "dockerfile"

_is_dockerfile(path) if contains(lower(path), "dockerfile.")

_is_dockerfile(path) if endswith(lower(path), ".dockerfile")

_strip_comment(line) := trimmed if {
	idx := indexof(line, "#")
	idx >= 0
	trimmed := trim_space(substring(line, 0, idx))
} else := trim_space(line)

_secret_keywords := {
	"passwd", "password", "pass", "secret", "key", "access",
	"api_key", "apikey", "token", "tkn",
}

_root_chown_patterns := {
	"--chown=root", "--chown=toor", "--chown=0",
	"--chown=root:root", "--chown=toor:toor", "--chown=0:0",
}

_forbidden_expose_ports := {"22", "3389"}

# Root-owned COPY/ADD
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := lower(_strip_comment(line))
	startswith(code, "copy ")
	some pattern in _root_chown_patterns
	contains(code, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("COPY uses root-owned chown flag %q; change ownership to a non-root user.", [pattern]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := lower(_strip_comment(line))
	startswith(code, "add ")
	some pattern in _root_chown_patterns
	contains(code, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ADD uses root-owned chown flag %q; change ownership to a non-root user.", [pattern]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": i + 1,
		"snippet": line,
	}
}

# Forbidden EXPOSE ports (SSH / RDP)
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := _strip_comment(line)
	startswith(lower(code), "expose ")
	some port in _forbidden_expose_ports
	regex.match(sprintf(`(?i)\b%s\b`, [port]), code)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container exposes forbidden port %s (SSH/RDP).", [port]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": i + 1,
		"snippet": line,
	}
}

# Secrets in ENV
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := lower(_strip_comment(line))
	startswith(code, "env ")
	some kw in _secret_keywords
	contains(code, kw)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential secret in ENV instruction (keyword %q).", [kw]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": i + 1,
		"snippet": line,
	}
}

# ADD used
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := lower(_strip_comment(line))
	startswith(code, "add ")
	not contains(code, "http")
	finding := {
		"rule_id": metadata.id,
		"message": "Use COPY instead of ADD for local files.",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": i + 1,
		"snippet": line,
	}
}

# :latest base tag
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := lower(_strip_comment(line))
	startswith(code, "from ")
	contains(code, ":latest")
	finding := {
		"rule_id": metadata.id,
		"message": "Do not use `:latest` tag on base images; pin to an immutable tag.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": i + 1,
		"snippet": line,
	}
}

# curl / wget in RUN
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := lower(_strip_comment(line))
	startswith(code, "run ")
	regex.match(`\b(curl|wget)\b`, code)
	finding := {
		"rule_id": metadata.id,
		"message": "Avoid curl/wget inside RUN; prefer package managers with checksums.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": i + 1,
		"snippet": line,
	}
}

# Package manager upgrade/update
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := lower(_strip_comment(line))
	startswith(code, "run ")
	regex.match(`(apk|yum|dnf|apt|apt-get|pip)[^\n]+(upgrade|dist-upgrade|update)`, code)
	finding := {
		"rule_id": metadata.id,
		"message": "Avoid in-place package upgrades; rebuild image from a newer base.",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": i + 1,
		"snippet": line,
	}
}

# Missing USER directive
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	user_lines := [i |
		some i
		line := lines[i]
		code := lower(_strip_comment(line))
		startswith(code, "user ")
	]
	count(user_lines) == 0
	from_lines := [i |
		some i
		line := lines[i]
		code := lower(_strip_comment(line))
		startswith(code, "from ")
	]
	count(from_lines) > 0
	finding := {
		"rule_id": metadata.id,
		"message": "No USER instruction found; container runs as root by default.",
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": from_lines[0] + 1,
		"snippet": lines[from_lines[0]],
	}
}
