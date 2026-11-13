# =============================================================================
# Reserved for Stage 2 — OCI infrastructure for the secrets sandbox
# =============================================================================
# Nothing in this directory creates a resource yet. Stage 1 only fixes the
# toolchain contract, so Stage 2 can add modules/network and modules/compute
# without renegotiating versions.
#
# The shape that will be provisioned (documented now so the security model is
# decided before the infrastructure exists):
#
#   VCN 10.6.0.0/16
#     └── subnet 10.6.1.0/24
#           └── A1.Flex, 1 OCPU / 1 GB (Always Free)
#                 security list: 22 from the operator CIDR only
#                ** no 8200 rule, ever — the API is private by construction **
#
# Port 8200 is reached over an SSH tunnel or from a peer inside the VCN. A
# secrets API with a public listener is a design error, not a hardening task.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 6.20.0, < 8.0.0"
    }
  }
}
