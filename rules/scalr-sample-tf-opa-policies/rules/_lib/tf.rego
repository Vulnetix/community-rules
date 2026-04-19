# Helper package — not a rule (no metadata/findings).
# Shared by the Scalr sample-tf-opa-policies Vulnetix ports.
#
# Upstream rules consumed Terraform plan JSON (input.tfplan.resource_changes)
# or Scalr runtime metadata (input.tfrun). Under Vulnetix we scan raw `.tf`
# source via input.file_contents, so we need regex helpers to pull resource
# blocks, attributes, and sub-blocks.

package vulnetix.scalr.tf

import rego.v1

is_tf(path) if endswith(lower(path), ".tf")

# Return every `resource "TYPE" "NAME" { ... }` block as text.
resource_blocks(content, type) := blocks if {
	pattern := sprintf(`(?s)resource\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
}

# Return every `data "TYPE" "NAME" { ... }` block as text.
data_blocks(content, type) := blocks if {
	pattern := sprintf(`(?s)data\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
}

# Extract the NAME portion (second quoted identifier) from a resource block.
resource_name(block) := name if {
	captures := regex.find_n(`"([^"]+)"`, block, 3)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}

# Extract the TYPE portion (first quoted identifier) from a resource block.
resource_type(block) := t if {
	captures := regex.find_n(`"([^"]+)"`, block, 3)
	count(captures) >= 1
	t := trim(captures[0], `"`)
}

# Printable address `TYPE.NAME`.
resource_address(block) := sprintf("%s.%s", [resource_type(block), resource_name(block)])

# Pull `key = "value"` string assignments from a block.
string_attr(block, key) := val if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	caps := regex.find_n(`"([^"]*)"`, matches[0], 1)
	count(caps) > 0
	val := trim(caps[0], `"`)
}

# Pull every `key = "value"` occurrence inside a block (recurses into sub-blocks).
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

# Pull every value from a list assignment `key = ["a", "b"]`.
string_list_attr(block, key) := vals if {
	pattern := sprintf(`(?s)%s\s*=\s*\[([^\]]*)\]`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	body := matches[0]
	items := regex.find_n(`"([^"]*)"`, body, -1)
	vals := [v | some i in items; v := trim(i, `"`)]
}

# Check if a block defines a named sub-block (e.g. `ingress { ... }`).
has_sub_block(block, name) if {
	regex.match(sprintf(`(?s)\b%s\s*\{`, [name]), block)
}

# Extract every sub-block body (e.g. every `ingress { ... }`) from a block.
sub_blocks(block, name) := subs if {
	pattern := sprintf(`(?s)\b%s\s*\{((?:[^{}]|\{[^{}]*\})*?)\}`, [name])
	matches := regex.find_n(pattern, block, -1)
	subs := matches
}

array_contains(arr, elem) if {
	some x in arr
	x == elem
}
