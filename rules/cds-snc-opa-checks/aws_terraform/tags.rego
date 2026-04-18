# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_required_tags

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-TAG-0001",
	"name": "AWS resources must carry CostCentre + Terraform tags",
	"description": "Any resource whose block declares a `tags = {...}` map must include the `CostCentre` and `Terraform` keys.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/resource-tagging",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "tagging", "governance"],
}

_minimum_tags := ["CostCentre", "Terraform"]

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)resource\s+"[^"]+"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, content, -1)
	some block in blocks
	regex.match(`(?s)\btags\s*=\s*\{`, block)
	missing := _missing_tags(block)
	count(missing) > 0
	header := regex.find_n(`resource\s+"[^"]+"\s+"[^"]+"`, block, 1)
	count(header) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s is missing required tag(s): %v.", [header[0], missing]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": header[0],
	}
}

_missing_tags(block) := missing if {
	missing := [tag |
		some tag in _minimum_tags
		not regex.match(sprintf(`(?m)"?%s"?\s*[:=]`, [tag]), block)
	]
}
