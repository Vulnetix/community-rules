# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_lambda_runtime

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-LAMBDA-0001",
	"name": "Lambda functions must use a supported runtime",
	"description": "`aws_lambda_function.runtime` must be one of the currently supported AWS Lambda runtimes when `package_type` is `Zip`.",
	"help_uri": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [1104],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "lambda", "runtime"],
}

_valid_runtimes := {
	"dotnet8",
	"dotnet7",
	"dotnet6",
	"nodejs22.x",
	"nodejs20.x",
	"nodejs18.x",
	"python3.13",
	"python3.12",
	"python3.11",
	"python3.10",
	"python3.9",
	"ruby3.3",
	"ruby3.2",
	"java21",
	"java17",
	"java11",
	"java8.al2",
	"go1.x",
	"provided.al2023",
	"provided.al2",
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_lambda_function")
	not _is_image_package(block)
	runtime := tf.string_attr(block, "runtime")
	not _valid_runtimes[runtime]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_lambda_function %q uses unsupported runtime %q.", [tf.resource_name(block), runtime]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": runtime,
	}
}

_is_image_package(block) if {
	regex.match(`(?m)package_type\s*=\s*"Image"`, block)
}
