# OCI provider.
#
# Authentication precedence:
#   1. config_file_profile (default "DEFAULT") — reads ~/.oci/config and the key
#      it references. Nothing sensitive enters this repository or the state.
#   2. inline user_ocid / fingerprint / private_key_path — for CI environments
#      that materialise a key file at runtime.
#
# PORTABILITY: on AWS this block becomes `provider "aws" { region = var.region }`
# and credentials come from the standard chain; on GCP, `provider "google" {
# project = var.project_id, region = var.region }`. The rest of the configuration
# does not change shape, only resource type names.

provider "oci" {
  tenancy_ocid        = var.tenancy_ocid
  region              = var.region
  config_file_profile = var.config_file_profile

  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
}
