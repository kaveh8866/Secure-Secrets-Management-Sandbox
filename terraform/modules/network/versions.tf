# The child module must declare the provider it expects. Without this entry the
# root's `providers = { oci = oci }` mapping is rejected with "Reference to
# undefined provider", because OpenTofu cannot tell which provider the module
# means — and an inferred default would be hashicorp/oci, not oracle/oci.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 6.20.0, < 8.0.0"
    }
  }
}
