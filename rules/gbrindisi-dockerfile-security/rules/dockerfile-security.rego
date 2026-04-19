# Adapted from https://github.com/gbrindisi/dockerfile-security
# Original License: GPL-3.0 (see LICENSE).
# Ported to the Vulnetix Rego input schema: `input.file_contents`
# maps file path -> full file text content.

package vulnetix.rules.gbrindisi_dockerfile_security

import rego.v1

metadata := {
	"id": "GBRI-DF-001",
	"name": "Dockerfile security hardening",
	"description": "Detects Dockerfile anti-patterns (secrets in ENV, untrusted base images, `latest` tags, `ADD` over `COPY`, sudo/curl bashing, running as root, untrusted packages).",
	"help_uri": "https://github.com/gbrindisi/dockerfile-security",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [250, 732, 798],
	"capec": ["CAPEC-507"],
	"attack_technique": ["T1610"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "container", "iac", "hardening"],
}

_is_dockerfile(path) if {
	lower_path := lower(path)
	endswith(lower_path, "/dockerfile")
}

_is_dockerfile(path) if {
	lower_path := lower(path)
	lower_path == "dockerfile"
}

_is_dockerfile(path) if {
	contains(lower(path), "dockerfile.")
}

_is_dockerfile(path) if {
	endswith(lower(path), ".dockerfile")
}

_secret_keywords := {
	"passwd", "password", "pass", "secret", "key", "access",
	"api_key", "apikey", "token", "tkn",
}

_strip_comment(line) := trimmed if {
	idx := indexof(line, "#")
	idx >= 0
	trimmed := trim_space(substring(line, 0, idx))
} else := trim_space(line)

_forbidden_user(name) if {
	lower_name := lower(name)
	lower_name in {"root", "toor", "0"}
}

# Secrets in ENV directives
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := _strip_comment(line)
	startswith(lower(code), "env ")
	some kw in _secret_keywords
	contains(lower(code), kw)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential secret in ENV instruction (keyword: %q)", [kw]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": i + 1,
		"snippet": line,
	}
}

# Use of :latest tag
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := _strip_comment(line)
	startswith(lower(code), "from ")
	contains(lower(code), ":latest")
	finding := {
		"rule_id": metadata.id,
		"message": "Avoid `:latest` tag for base images; pin to a specific version.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": i + 1,
		"snippet": line,
	}
}

# ADD used (should prefer COPY)
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := _strip_comment(line)
	startswith(lower(code), "add ")
	not contains(lower(code), "http")
	finding := {
		"rule_id": metadata.id,
		"message": "Use `COPY` instead of `ADD` for local files.",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": i + 1,
		"snippet": line,
	}
}

# sudo used inside RUN
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := _strip_comment(line)
	startswith(lower(code), "run ")
	regex.match(`\bsudo\b`, lower(code))
	finding := {
		"rule_id": metadata.id,
		"message": "`sudo` used in RUN instruction; container processes should not rely on sudo.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": i + 1,
		"snippet": line,
	}
}

# curl | sh / wget | sh pattern
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := _strip_comment(line)
	startswith(lower(code), "run ")
	matches := regex.find_n(`(curl|wget)[^|^>]*[|>]`, lower(code), -1)
	count(matches) > 0
	finding := {
		"rule_id": metadata.id,
		"message": "Avoid curl/wget piped to shell; verify and install packages via a package manager with checksums.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": i + 1,
		"snippet": line,
	}
}

# Package manager upgrade/update in RUN
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	some i
	line := lines[i]
	code := _strip_comment(line)
	startswith(lower(code), "run ")
	regex.match(`(apk|yum|dnf|apt|apt-get|pip)[^\n]+(upgrade|dist-upgrade|update)`, lower(code))
	finding := {
		"rule_id": metadata.id,
		"message": "Avoid in-place package upgrades; rebuild the image against a newer base instead.",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": i + 1,
		"snippet": line,
	}
}

# Final USER is root/toor/0
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	users := [user_info |
		lines := split(content, "\n")
		some i
		line := lines[i]
		code := _strip_comment(line)
		startswith(lower(code), "user ")
		user_info := {
			"line": i + 1,
			"name": trim_space(substring(code, 5, -1)),
			"snippet": line,
		}
	]
	count(users) > 0
	last := users[count(users) - 1]
	_forbidden_user(last.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Final USER directive is forbidden (%q); run as a non-root user.", [last.name]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": last.line,
		"snippet": last.snippet,
	}
}

# No USER directive at all
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	lines := split(content, "\n")
	user_lines := [i |
		some i
		line := lines[i]
		code := _strip_comment(line)
		startswith(lower(code), "user ")
	]
	count(user_lines) == 0
	from_lines := [i |
		some i
		line := lines[i]
		code := _strip_comment(line)
		startswith(lower(code), "from ")
	]
	count(from_lines) > 0
	finding := {
		"rule_id": metadata.id,
		"message": "Dockerfile has no USER instruction; the image will run as root.",
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": from_lines[0] + 1,
		"snippet": lines[from_lines[0]],
	}
}
