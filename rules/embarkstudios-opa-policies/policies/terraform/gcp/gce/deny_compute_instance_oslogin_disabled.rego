# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_39

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-39",
	"name": "Compute instance must enable OS Login",
	"description": "TF_GCP_39: google_compute_instance must set metadata.enable-oslogin = \"TRUE\".",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_39",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-287"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "ssh", "oslogin"],
}

findings contains finding if {
	some r in tf.resources("google_compute_instance")
	not _has_oslogin_true(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Compute instance %q does not enable OS Login.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_oslogin_true(block) if {
	regex.match(`(?i)enable-oslogin\s*=\s*"TRUE"`, block)
}
