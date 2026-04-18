# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_26

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-26",
	"name": "GKE cluster must use REGULAR release channel",
	"description": "TF_GCP_26: google_container_cluster must set release_channel.channel = REGULAR.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_26",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "patching"],
}

findings contains finding if {
	some r in tf.resources("google_container_cluster")
	not _has_regular_channel(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q release_channel is not REGULAR.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_regular_channel(block) if {
	some sub in tf.sub_blocks(block, "release_channel")
	tf.string_attr(sub, "channel") == "REGULAR"
}
