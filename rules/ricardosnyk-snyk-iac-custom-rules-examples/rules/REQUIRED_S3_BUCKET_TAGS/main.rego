# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.ricardo_s3_required_tags

import rego.v1

import data.vulnetix.ricardosnyk.relations

metadata := {
	"id": "RICARDO-S3-TAGS-001",
	"name": "S3 bucket must declare owner and classification tags",
	"description": "Each `aws_s3_bucket` must declare `tags.owner` (from allowed team list) and `tags.classification` (public|internal|confidential).",
	"help_uri": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "s3", "tagging"],
}

_allowed_owners := {"devteam1", "devteam2", "devteam3", "devteam4"}
_allowed_classifications := {"public", "internal", "confidential"}

findings contains finding if {
	some path, content in input.file_contents
	relations.is_tf(path)
	some block in relations.resource_blocks(content, "aws_s3_bucket")
	name := relations.resource_name(block)
	not _valid_owner(block)
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q missing or unknown tags.owner.", [name]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": relations.line_of(content, offset),
		"snippet": sprintf("aws_s3_bucket %q", [name]),
	}
}

findings contains finding if {
	some path, content in input.file_contents
	relations.is_tf(path)
	some block in relations.resource_blocks(content, "aws_s3_bucket")
	name := relations.resource_name(block)
	not _valid_classification(block)
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_s3_bucket %q missing or unknown tags.classification.", [name]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": relations.line_of(content, offset),
		"snippet": sprintf("aws_s3_bucket %q", [name]),
	}
}

_valid_owner(block) if {
	m := regex.find_n(`owner\s*=\s*"([^"]+)"`, block, 1)
	count(m) > 0
	v := regex.replace(m[0], `.*"([^"]+)".*`, "$1")
	_allowed_owners[v]
}

_valid_classification(block) if {
	m := regex.find_n(`classification\s*=\s*"([^"]+)"`, block, 1)
	count(m) > 0
	v := regex.replace(m[0], `.*"([^"]+)".*`, "$1")
	_allowed_classifications[v]
}
