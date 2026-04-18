# Adapted from EmbarkStudios/opa-policies.
# Dockerfile parsing helpers for the Vulnetix port.

package vulnetix.embark.docker

import rego.v1

is_dockerfile_path(path) if endswith(lower(path), "dockerfile")

is_dockerfile_path(path) if endswith(lower(path), ".dockerfile")

# Normalise: join Dockerfile line continuations (\<newline>) into single lines.
_normalised(content) := replace(content, "\\\n", " ")

# Simple Dockerfile instruction parser:
#   - drops comments & blank lines
#   - splits into [cmd, value]; cmd lower-cased.
instructions(content) := out if {
	lines := split(_normalised(content), "\n")
	out := [inst |
		some line in lines
		trimmed := trim_space(line)
		trimmed != ""
		not startswith(trimmed, "#")
		parts := regex.split(`\s+`, trimmed)
		count(parts) >= 2
		cmd := lower(parts[0])
		value := trim_space(substring(trimmed, count(parts[0]), -1))
		inst := {"cmd": cmd, "value": value}
	]
}

froms(content) := out if {
	out := [from |
		some inst in instructions(content)
		inst.cmd == "from"
		from := trim_space(regex.split(`\s+(AS|as|As|aS)\s+`, inst.value)[0])
	]
}

runs(content) := out if {
	out := [run | some inst in instructions(content); inst.cmd == "run"; run := inst.value]
}

exposes(content) := out if {
	out := [port |
		some inst in instructions(content)
		inst.cmd == "expose"
		port := trim_space(regex.split(`\s+`, inst.value)[0])
	]
}

users(content) := out if {
	out := [user |
		some inst in instructions(content)
		inst.cmd == "user"
		user := trim_space(inst.value)
	]
}

adds(content) := out if {
	out := [a | some inst in instructions(content); inst.cmd == "add"; a := inst.value]
}

has_user_set(content) if {
	some inst in instructions(content)
	inst.cmd == "user"
}
