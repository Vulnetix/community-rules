# Helper package — not a rule (no metadata/findings).
# Shared by the EmbarkStudios/opa-policies Terraform/GCP Vulnetix ports.
#
# Upstream rules consumed `input.resource.<type>.<name>` (terraform HCL parsed
# by conftest). Under Vulnetix we scan raw `.tf` source via input.file_contents,
# so this provides regex helpers to pull resource blocks and attributes.

package vulnetix.embark.tf

import rego.v1

is_tf(path) if endswith(lower(path), ".tf")

# Every `resource "TYPE" "NAME" { ... }` block in a file as a record
# {"block": "<text>", "name": "<NAME>", "type": "<TYPE>"}.
resource_blocks(content, type) := out if {
	pattern := sprintf(`(?s)resource\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
	out := [r |
		some b in blocks
		name := _block_name(b)
		r := {"block": b, "name": name, "type": type}
	]
}

# Cross-file iteration: every matching resource across input.file_contents.
resources(type) := out if {
	out := [r |
		some path, content in input.file_contents
		is_tf(path)
		some rb in resource_blocks(content, type)
		r := {"path": path, "block": rb.block, "name": rb.name, "type": rb.type}
	]
}

_block_name(block) := name if {
	captures := regex.find_n(`"([^"]+)"`, block, 2)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}

# `key = "value"` — first match.
string_attr(block, key) := val if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	caps := regex.find_n(`"([^"]*)"`, matches[0], 1)
	count(caps) > 0
	val := trim(caps[0], `"`)
}

# Every `key = "value"` occurrence (recurses into sub-blocks).
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

# `key = true` / `key = false` as boolean; unset → undefined.
bool_attr(block, key) := b if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*(true|false)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	b := regex.match(`=\s*true\b`, matches[0])
}

# `key = <number>` as number.
number_attr(block, key) := n if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*([0-9]+)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	digits := regex.find_n(`[0-9]+`, matches[0], -1)
	count(digits) > 0
	n := to_number(digits[count(digits) - 1])
}

# Every value inside `key = ["a", "b"]`.
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

# Missing attribute, OR attribute present and "true".
not_existing_or_true(block, key) if not has_key(block, key)
not_existing_or_true(block, key) if bool_attr(block, key) == true
not_existing_or_true(block, key) if string_attr(block, key) == "true"

# Attribute explicitly set to false.
is_false(block, key) if bool_attr(block, key) == false

is_false(block, key) if string_attr(block, key) == "false"

# Attribute is NOT explicitly set to true (missing OR set to anything else).
# Use this instead of `not bool_attr(block, key) == true` which doesn't work
# in Rego v1 when bool_attr is undefined.
is_not_true(block, key) if not has_key(block, key)
is_not_true(block, key) if bool_attr(block, key) == false
is_not_true(block, key) if string_attr(block, key) == "false"

# Attribute is NOT explicitly set to false (missing OR set to anything else).
is_not_false(block, key) if not has_key(block, key)
is_not_false(block, key) if bool_attr(block, key) == true
is_not_false(block, key) if string_attr(block, key) == "true"

# Rule ID helper.
help_uri(check) := sprintf("https://github.com/EmbarkStudios/opa-policies/wiki/%s", [check])

default_service_account_regexp := `.*-compute@developer.gserviceaccount.com|.*@appspot.gserviceaccount.com|.*@cloudbuild.gserviceaccount.com`

public_users := {"allUsers", "allAuthenticatedUsers"}

impersonation_roles := {"roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"}
