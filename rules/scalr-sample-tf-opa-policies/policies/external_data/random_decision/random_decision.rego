# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# NOTE: Upstream is a demo of http.send to random.org. Vulnetix scans offline,
# so this port declares metadata but never emits findings. Retaining the file
# preserves attribution and documents why the demo cannot be evaluated here.

package vulnetix.rules.scalr_random_decision

import rego.v1

metadata := {
	"id": "SCALR-DEMO-0001",
	"name": "Demo: external HTTP policy decision (no-op under text scanning)",
	"description": "Upstream uses http.send to random.org. Vulnetix scans offline, so this port is intentionally non-firing.",
	"help_uri": "https://github.com/Scalr/sample-tf-opa-policies/blob/master/policies/external_data/random_decision/random_decision.rego",
	"languages": ["terraform"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["demo", "http"],
}

findings := set()
