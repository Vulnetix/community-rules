# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).
#
# Upstream pulled provider regions from the plan configuration tree. Under
# text scanning we check the AWS `provider "aws" { region = "..." }` block,
# the azurerm resource `location` attribute, and the google resource `zone`
# attribute — each against its provider-specific allow-list.

package vulnetix.rules.scalr_cloud_location

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-PLACE-0001",
	"name": "Cloud resources must be placed in approved regions/zones",
	"description": "AWS `provider \"aws\" { region }`, Azure `location`, and GCP `zone` values must fall within per-provider allow-lists.",
	"help_uri": "",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "placement", "governance"],
}

_aws_regions := {"us-east-1", "us-east-2"}

_azure_locations := {"eastus", "eastus2"}

_gcp_zones := {"us-central1-a", "us-central1-b", "us-west1-a"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)provider\s+"aws"\s*\{(?:[^{}]|\{[^{}]*\})*?\}`, content, -1)
	some block in blocks
	region := tf.string_attr(block, "region")
	not _aws_regions[region]
	finding := _place_finding(path, sprintf("provider.aws (region=%s)", [region]), region)
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	azure_types := regex.find_n(`(?s)resource\s+"azurerm_[^"]+"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, content, -1)
	some block in azure_types
	location := tf.string_attr(block, "location")
	not _azure_locations[location]
	finding := _place_finding(path, tf.resource_address(block), location)
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	google_types := regex.find_n(`(?s)resource\s+"google_[^"]+"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, content, -1)
	some block in google_types
	zone := tf.string_attr(block, "zone")
	not _gcp_zones[zone]
	finding := _place_finding(path, tf.resource_address(block), zone)
}

_place_finding(path, address, location) := finding if {
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s uses location %q which is not in the allow-list.", [address, location]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": location,
	}
}
