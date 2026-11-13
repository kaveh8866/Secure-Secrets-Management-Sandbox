# OCI network module — public VCN with one public subnet and a two-rule ingress.
#
# PORTABILITY — the same five resources on the other providers:
#
#   | OCI (here)                | AWS                          | GCP                                |
#   | ------------------------- | ---------------------------- | ---------------------------------- |
#   | oci_core_vcn              | aws_vpc                      | google_compute_network             |
#   | oci_core_internet_gateway | aws_internet_gateway         | (implicit with a default route)    |
#   | oci_core_route_table      | aws_route_table + aws_route   | google_compute_route               |
#   | oci_core_security_list    | aws_security_group + rules    | google_compute_firewall            |
#   | oci_core_subnet           | aws_subnet                   | google_compute_subnetwork          |
#
# The ingress contract (SSH from the operator CIDR, API from the operator CIDR)
# maps to one security-group rule set on AWS and one firewall rule set on GCP.
# Nothing else in the module is OCI-specific.
#
# SECURITY POSTURE — deliberately two rules, not three:
#
#   Inbound 22/tcp      from ssh_allowed_cidr
#   Inbound <api_port>  from api_allowed_cidr   (8200: the secrets API)
#   Inbound everything else: denied by omission.
#
# There is no 80/443 rule because this host serves no web UI. Adding one "to see
# if it works" would put a secrets API behind a browser-facing port, which is the
# exact mistake this project exists to avoid.

locals {
  ingress_rules = [
    {
      description = "SSH administration from the operator network"
      port        = 22
      cidr        = var.ssh_allowed_cidr
    },
    {
      description = "Secrets API (bearer-token authenticated, no TLS on the wire)"
      port        = var.api_port
      cidr        = var.api_allowed_cidr
    },
  ]
}

resource "oci_core_vcn" "this" {
  compartment_id = var.compartment_id
  cidr_block     = var.vcn_cidr
  display_name   = "${var.name_prefix}-vcn"
  dns_label      = var.vcn_dns_label
  freeform_tags  = var.freeform_tags
}

resource "oci_core_internet_gateway" "this" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${var.name_prefix}-igw"
  enabled        = true
  freeform_tags  = var.freeform_tags
}

# Dedicated route table instead of mutating the VCN default, so routing intent is
# visible in the plan and the VCN stays reusable.
resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${var.name_prefix}-public-rt"
  freeform_tags  = var.freeform_tags

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.this.id
    description       = "Default IPv4 egress to the internet gateway"
  }
}

resource "oci_core_security_list" "public" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${var.name_prefix}-sl"
  freeform_tags  = var.freeform_tags

  dynamic "ingress_security_rules" {
    for_each = local.ingress_rules

    content {
      protocol    = "6" # TCP
      source      = ingress_security_rules.value.cidr
      source_type = "CIDR_BLOCK"
      description = ingress_security_rules.value.description

      tcp_options {
        min = ingress_security_rules.value.port
        max = ingress_security_rules.value.port
      }
    }
  }

  # Egress stays open: OS updates, container image pulls on boot, and no need to
  # re-plan the network when a dependency host changes. Egress filtering belongs
  # at the proxy if this ever leaves a sandbox.
  egress_security_rules {
    protocol         = "all"
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    description      = "Allow all egress (OS updates, image pulls)"
  }
}

resource "oci_core_subnet" "public" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.this.id
  cidr_block                 = var.subnet_cidr
  display_name               = "${var.name_prefix}-public-subnet"
  dns_label                  = var.subnet_dns_label
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.public.id]
  prohibit_public_ip_on_vnic = false
  freeform_tags              = var.freeform_tags
}
