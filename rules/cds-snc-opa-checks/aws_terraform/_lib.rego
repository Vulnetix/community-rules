# Helper package — not a rule (no metadata/findings).
# Shared by the cds-snc aws_terraform Vulnetix ports.
#
# Upstream rules expected `terraform show -json plan.tfplan` input. Under
# Vulnetix `input.file_contents` we scan the raw `.tf` source instead, so
# we need regex helpers to pull resource blocks and their attributes.

package vulnetix.cds_snc.tf

import rego.v1

is_tf(path) if endswith(lower(path), ".tf")

# Return the full text of every `resource "TYPE" "NAME" { ... }` block.
# Handles one level of nested braces.
resource_blocks(content, type) := blocks if {
	pattern := sprintf(`(?s)resource\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{[^{}]*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
}

# Extract the NAME portion (second quoted identifier) from a resource block.
resource_name(block) := name if {
	captures := regex.find_n(`"([^"]+)"`, block, 3)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}

# Pull `key = "value"` string assignments from a block.
string_attr(block, key) := val if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	parts := regex.find_n(`"([^"]*)"`, matches[0], 1)
	count(parts) > 0
	val := trim(parts[0], `"`)
}

# Pull a bare (unquoted) value for `key = <token>` — numbers, identifiers.
raw_attr(block, key) := val if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*([^\s"][^\s#]*)`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	val := trim_space(regex.replace(matches[0], sprintf(`(?m)^\s*%s\s*=\s*`, [key]), ""))
}

# Check if a block defines a named sub-block (e.g. `egress { ... }`).
has_sub_block(block, name) if {
	regex.match(sprintf(`(?s)\b%s\s*\{`, [name]), block)
}

# Extract every sub-block body (e.g. every `egress { ... }` body) from a
# resource block. Handles one level of nested braces.
sub_blocks(block, name) := subs if {
	pattern := sprintf(`(?s)\b%s\s*\{((?:[^{}]|\{[^{}]*\})*?)\}`, [name])
	matches := regex.find_n(pattern, block, -1)
	subs := matches
}

# Block header `resource "TYPE" "NAME"` as a printable address.
resource_address(block) := addr if {
	header := regex.find_n(`resource\s+"([^"]+)"\s+"([^"]+)"`, block, 1)
	count(header) > 0
	caps := regex.find_n(`"([^"]+)"`, header[0], 2)
	count(caps) >= 2
	addr := sprintf("%s.%s", [trim(caps[0], `"`), trim(caps[1], `"`)])
}
