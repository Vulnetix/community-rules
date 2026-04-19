# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Helper package — not a rule (no metadata/findings).
# Under Vulnetix's text-scanning model, rules perform joins by matching
# referenced resource names via regex rather than via snyk.relates().

package vulnetix.ricardosnyk.relations

import rego.v1

is_tf(path) if endswith(lower(path), ".tf")

line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

resource_name(block) := name if {
	captures := regex.find_n(`"([^"]+)"`, block, 3)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}

resource_blocks(content, type) := blocks if {
	pattern := sprintf(`(?s)resource\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{[^{}]*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
}
