# Helper package — not a rule (no metadata/findings).
# Shared by the Cigna/confectionery Vulnetix ports.
#
# Upstream rules use the Fugue Regula framework's parsed-HCL schema via
# `data.fugue.resources(<type>)`. Under Vulnetix we scan raw `.tf` via
# input.file_contents, so this provides regex helpers to pull resource blocks,
# attributes, and sub-blocks.

package vulnetix.cigna.tf

import rego.v1

is_tf(path) if endswith(lower(path), ".tf")

resource_blocks(content, type) := out if {
	pattern := sprintf(`(?s)resource\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
	out := [r |
		some b in blocks
		name := _block_name(b)
		r := {"block": b, "name": name, "type": type}
	]
}

resources(type) := out if {
	out := [r |
		some path, content in input.file_contents
		is_tf(path)
		some rb in resource_blocks(content, type)
		r := {"path": path, "block": rb.block, "name": rb.name, "type": rb.type}
	]
}

data_blocks(content, type) := out if {
	pattern := sprintf(`(?s)data\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
	out := [r |
		some b in blocks
		name := _block_name(b)
		r := {"block": b, "name": name, "type": type}
	]
}

data_sources(type) := out if {
	out := [r |
		some path, content in input.file_contents
		is_tf(path)
		some rb in data_blocks(content, type)
		r := {"path": path, "block": rb.block, "name": rb.name, "type": rb.type}
	]
}

_block_name(block) := name if {
	captures := regex.find_n(`"([^"]+)"`, block, 2)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}

string_attr(block, key) := val if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	caps := regex.find_n(`"([^"]*)"`, matches[0], 1)
	count(caps) > 0
	val := trim(caps[0], `"`)
}

string_attrs(block, key) := vals if {
	pattern := sprintf(`(?m)%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, -1)
	vals := [v |
		some m in matches
		caps := regex.find_n(`"([^"]*)"`, m, 1)
		count(caps) > 0
		v := trim(caps[0], `"`)
	]
}

bool_attr(block, key) := b if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*(true|false)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	b := regex.match(`=\s*true\b`, matches[0])
}

number_attr(block, key) := n if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*([0-9]+)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	digits := regex.find_n(`[0-9]+`, matches[0], -1)
	count(digits) > 0
	n := to_number(digits[count(digits) - 1])
}

string_list_attr(block, key) := vals if {
	pattern := sprintf(`(?s)%s\s*=\s*\[([^\]]*)\]`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	body := matches[0]
	items := regex.find_n(`"([^"]*)"`, body, -1)
	vals := [v | some i in items; v := trim(i, `"`)]
}

has_key(block, key) if {
	pattern := sprintf(`(?m)^\s*%s\s*=`, [key])
	regex.match(pattern, block)
}

has_sub_block(block, name) if {
	regex.match(sprintf(`(?s)\b%s\s*\{`, [name]), block)
}

sub_blocks(block, name) := subs if {
	pattern := sprintf(`(?s)\b%s\s*\{((?:[^{}]|\{[^{}]*\})*?)\}`, [name])
	subs := regex.find_n(pattern, block, -1)
}

is_not_true(block, key) if not has_key(block, key)
is_not_true(block, key) if bool_attr(block, key) == false
is_not_true(block, key) if string_attr(block, key) == "false"

is_not_false(block, key) if not has_key(block, key)
is_not_false(block, key) if bool_attr(block, key) == true
is_not_false(block, key) if string_attr(block, key) == "true"

# Extract heredoc bodies from a block: `key = <<EOF\n...\nEOF` → list of body strings.
heredoc_attrs(block, key) := out if {
	pattern := sprintf(`(?s)%s\s*=\s*<<-?([A-Za-z0-9_]+)\s*\n(.*?)\n\s*\1\b`, [key])
	matches := regex.find_all_string_submatch_n(pattern, block, -1)
	out := [m[2] | some m in matches]
}

# Attempt to detect a wildcard `*` IAM statement within a block's policy text
# (heredoc JSON, quoted JSON, or jsonencode-like HCL map). Best-effort: matches
# any "Effect":"Allow" adjacent to Action `*` and Resource `*`.
has_wildcard_allow_star(block) if {
	# Heredoc or string-literal JSON form.
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Action"\s*:\s*"\*"[\s\S]*?"Resource"\s*:\s*"\*"`, block)
}

has_wildcard_allow_star(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Resource"\s*:\s*"\*"[\s\S]*?"Action"\s*:\s*"\*"`, block)
}

has_wildcard_allow_star(block) if {
	# jsonencode HCL form: `Effect = "Allow"`, `Action = "*"`, `Resource = "*"`.
	regex.match(`(?s)Effect\s*=\s*"Allow"[\s\S]*?Action\s*=\s*"\*"[\s\S]*?Resource\s*=\s*"\*"`, block)
}

has_wildcard_allow_star(block) if {
	regex.match(`(?s)Effect\s*=\s*"Allow"[\s\S]*?Resource\s*=\s*"\*"[\s\S]*?Action\s*=\s*"\*"`, block)
}

# Detect `"Action":"<service>:*"` wildcard in a policy block.
has_service_star_action(block) if {
	regex.match(`"Action"\s*:\s*"[A-Za-z0-9\-]+:\*"`, block)
}

has_service_star_action(block) if {
	regex.match(`Action\s*=\s*"[A-Za-z0-9\-]+:\*"`, block)
}

# Detect `"NotAction"` in a policy block.
has_not_action(block) if {
	regex.match(`"NotAction"\s*:`, block)
}

has_not_action(block) if {
	regex.match(`\bNotAction\s*=`, block)
}

# Detect Principal wildcard with no Condition limiter.
has_wildcard_principal_without_condition(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Principal"\s*:\s*"\*"`, block)
	not regex.match(`"Condition"\s*:`, block)
}

has_wildcard_principal_without_condition(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Principal"\s*:\s*\{[^}]*"AWS"\s*:\s*"\*"`, block)
	not regex.match(`"Condition"\s*:`, block)
}
