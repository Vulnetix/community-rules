# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Helper package — not a rule (no metadata/findings).

package vulnetix.rallyhealth.docker_utils

import rego.v1

is_dockerfile(path) if endswith(lower(path), "/dockerfile")

is_dockerfile(path) if lower(path) == "dockerfile"

is_dockerfile(path) if contains(lower(path), "dockerfile.")

is_dockerfile(path) if endswith(lower(path), ".dockerfile")

strip_comment(line) := trimmed if {
	idx := indexof(line, "#")
	idx >= 0
	trimmed := trim_space(substring(line, 0, idx))
} else := trim_space(line)

# Collect all FROM image values (first token after FROM) from a Dockerfile.
from_images(content) := imgs if {
	lines := split(content, "\n")
	imgs := [img |
		some i
		line := lines[i]
		code := strip_comment(line)
		startswith(lower(code), "from ")
		rest := trim_space(substring(code, 5, -1))
		tokens := split(rest, " ")
		count(tokens) > 0
		img := tokens[0]
	]
}

# Collect stage names (AS <name>) declared in a Dockerfile.
stage_names(content) := names if {
	matches := regex.find_n(`(?i)FROM\s+\S+\s+AS\s+(\S+)`, content, -1)
	names := [n |
		some m in matches
		parts := regex.find_n(`(?i)AS\s+(\S+)`, m, 1)
		count(parts) > 0
		n := trim_space(regex.replace(parts[0], `(?i)AS\s+`, ""))
	]
}
