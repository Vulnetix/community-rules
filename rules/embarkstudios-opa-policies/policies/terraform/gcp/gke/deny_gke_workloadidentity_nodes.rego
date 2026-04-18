# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_25

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-25",
	"name": "GKE node pool must enable Workload Identity",
	"description": "TF_GCP_25: node_config.workload_metadata_config must set mode=GKE_METADATA (or legacy node_metadata=GKE_METADATA_SERVER).",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_25",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "workload-identity"],
}

findings contains finding if {
	some r in tf.resources("google_container_node_pool")
	not _workload_identity_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Node pool %q does not enable Workload Identity.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_workload_identity_enabled(block) if {
	regex.match(`(?m)^\s*mode\s*=\s*"GKE_METADATA"`, block)
}

_workload_identity_enabled(block) if {
	regex.match(`(?m)^\s*node_metadata\s*=\s*"GKE_METADATA_SERVER"`, block)
}
