variable "compartment_id" {
  description = "Compartment that owns the VCN and its child resources."
  type        = string
}

variable "name_prefix" {
  description = "Prefix applied to every resource display name."
  type        = string
}

variable "vcn_cidr" {
  description = "CIDR block for the VCN."
  type        = string

  validation {
    condition     = can(cidrhost(var.vcn_cidr, 0))
    error_message = "vcn_cidr must be a valid IPv4 CIDR block."
  }
}

variable "subnet_cidr" {
  description = "CIDR block for the public subnet. Must sit inside vcn_cidr."
  type        = string

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "subnet_cidr must be a valid IPv4 CIDR block."
  }
}

variable "ssh_allowed_cidr" {
  description = "Source CIDR allowed to reach 22/tcp."
  type        = string

  validation {
    condition     = can(cidrhost(var.ssh_allowed_cidr, 0))
    error_message = "ssh_allowed_cidr must be a valid IPv4 CIDR block."
  }
}

variable "api_allowed_cidr" {
  description = <<-EOT
    Source CIDR allowed to reach the secrets API. The module refuses 0.0.0.0/0:
    an API that hands out credentials must not be world-reachable, even with
    bearer auth and even in a sandbox.
  EOT
  type        = string

  validation {
    condition     = can(cidrhost(var.api_allowed_cidr, 0)) && var.api_allowed_cidr != "0.0.0.0/0"
    error_message = "api_allowed_cidr must be a specific IPv4 CIDR (the operator network), never 0.0.0.0/0."
  }
}

variable "api_port" {
  description = "TCP port the secrets API listens on."
  type        = number
  default     = 8200

  validation {
    condition     = var.api_port >= 1024 && var.api_port <= 65535
    error_message = "api_port must be an unprivileged port (1024-65535)."
  }
}

variable "vcn_dns_label" {
  description = "DNS label for the VCN (alphanumeric, no hyphens)."
  type        = string
  default     = "cloudguardsecrets"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9]{0,14}$", var.vcn_dns_label))
    error_message = "vcn_dns_label must be alphanumeric, start with a letter and be at most 15 characters."
  }
}

variable "subnet_dns_label" {
  description = "DNS label for the subnet (alphanumeric, no hyphens)."
  type        = string
  default     = "secrets"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9]{0,14}$", var.subnet_dns_label))
    error_message = "subnet_dns_label must be alphanumeric, start with a letter and be at most 15 characters."
  }
}

variable "freeform_tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
