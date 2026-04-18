# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_api_gateway_integration_uri

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-APIGW-0001",
	"name": "API Gateway integrations must use a properly formatted URI",
	"description": "`aws_api_gateway_integration` resources with `type` in {AWS, AWS_PROXY} must have an `arn:aws:apigateway:...` URI; HTTP/HTTP_PROXY types must have an http(s):// URI.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_integration",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "api-gateway"],
}

_aws_types := {"AWS", "AWS_PROXY"}

_http_types := {"HTTP", "HTTP_PROXY"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_api_gateway_integration")
	type_val := tf.string_attr(block, "type")
	uri := tf.string_attr(block, "uri")
	_aws_types[type_val]
	not regex.match(`^arn:aws:apigateway:[[:alnum:],-]+:[[:alnum:],-]+:[[:alnum:],-]+/.+$`, uri)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_api_gateway_integration %q uses type %q but URI %q is not a valid apigateway ARN.", [tf.resource_name(block), type_val, uri]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": uri,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_api_gateway_integration")
	type_val := tf.string_attr(block, "type")
	uri := tf.string_attr(block, "uri")
	_http_types[type_val]
	not regex.match(`^(http|https)://.+$`, uri)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_api_gateway_integration %q uses type %q but URI %q is not an http(s):// URL.", [tf.resource_name(block), type_val, uri]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": uri,
	}
}
