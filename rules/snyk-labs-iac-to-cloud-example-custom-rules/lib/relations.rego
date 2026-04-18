# Adapted from https://github.com/snyk-labs/iac-to-cloud-example-custom-rules
# Original License: Apache-2.0 (see LICENSE).
# Helper package — not a rule (no metadata/findings).
# Upstream used snyk.relates() to join parsed Terraform resources across
# different resource types. Under Vulnetix's text-scanning model, rules
# perform joins by matching referenced resource names via regex.

package vulnetix.snyk_labs.relations

import rego.v1
