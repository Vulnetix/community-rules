# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_20

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-20",
	"name": "Compute instance must enable Shielded VM secure boot",
	"description": "TF_GCP_20: google_compute_instance must set shielded_instance_config.secure_boot_enabled = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_20",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1188"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "shielded-vm"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	not _secure_boot_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Compute instance %q does not enable secure boot.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_secure_boot_enabled(block) if {
	regex.match(`(?m)^\s*secure_boot_enabled\s*=\s*true\b`, block)
}
