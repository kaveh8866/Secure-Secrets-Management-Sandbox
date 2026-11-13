# Reserved for Stage 2. Declared now so the interface is reviewable before any
# resource exists, and so `terraform.tfvars.example` has a contract to satisfy.
#
# Every variable here is either an identifier (not a secret) or a policy input.
# No private key, token or master key is ever a Terraform variable: those are
# injected at runtime, never provisioned.

variable "tenancy_ocid" {
  description = "OCI tenancy identifier."
  type        = string
}

variable "compartment_ocid" {
  description = "Compartment that owns every resource of this project."
  type        = string
}

variable "region" {
  description = "OCI region, e.g. eu-frankfurt-1."
  type        = string
  default     = "eu-frankfurt-1"
}

variable "config_file_profile" {
  description = "Profile name inside ~/.oci/config."
  type        = string
  default     = "DEFAULT"
}

variable "project_name" {
  description = "Prefix applied to every resource display name."
  type        = string
  default     = "cloudguard-secrets"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.project_name))
    error_message = "project_name must be lowercase, start with a letter, and be 3-31 characters."
  }
}

variable "ssh_public_key" {
  description = "Public key for the ubuntu user. The private half never leaves the operator machine."
  type        = string
}

variable "ssh_allowed_cidr" {
  description = "Single CIDR allowed to reach port 22. Never 0.0.0.0/0."
  type        = string

  validation {
    condition     = var.ssh_allowed_cidr != "0.0.0.0/0"
    error_message = "Port 22 must not be open to the world."
  }
}

variable "availability_domain" {
  description = "AD for the A1.Flex instance. AD-2 is used because AD-1 has been capacity-constrained."
  type        = string
}

variable "instance_ocpus" {
  description = "OCPUs for the Always Free A1.Flex shape."
  type        = number
  default     = 1
}

variable "instance_memory_gb" {
  description = "Memory in GB. The service caps itself at 128 MiB, so 1 GB is generous."
  type        = number
  default     = 1
}

variable "boot_volume_gb" {
  description = "Boot volume size in GB (200 GB are free across the tenancy)."
  type        = number
  default     = 50
}
