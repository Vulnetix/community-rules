# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_43

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-43",
	"name": "IAP web IAM member should set a host condition",
	"description": "TF_GCP_43: google_iap_web_iam_member must include a condition.expression containing `request.host`.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_43",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "iap"],
}

findings contains finding if {
	some r in tf.resources("google_iap_web_iam_member")
	exprs := tf.string_attrs(r.block, "expression")
	not _any_has_request_host(exprs)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAP IAM member %q has no host condition.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_any_has_request_host(exprs) if {
	some e in exprs
	contains(e, "request.host")
}
