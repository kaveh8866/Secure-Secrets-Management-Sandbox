# Terraform / OpenTofu — OCI infrastructure

Provisions the host for the secrets sandbox on Oracle Cloud Infrastructure:
a VCN, an internet gateway, a public subnet, a two-rule security list and one
Always Free Ampere instance. **OCI is the validated target.** AWS and GCP are
supported *ports* — the mappings are documented here and in comments, but this
repository contains no test evidence for them.

```
terraform/
├── provider.tf              OCI provider (profile-based auth, no key in state)
├── main.tf                  module wiring, tags, cloud-init rendering
├── variables.tf             full input contract
├── outputs.tf               public IP, API URL, exposure review
├── cloud-init.yaml.tftpl    Docker + hardening; contains no secret
├── terraform.tfvars.example placeholders only
└── modules/
    ├── network/             VCN, IGW, route table, security list, subnet
    └── compute/             A1.Flex instance, VNIC IPs, image resolution
```

## Ingress contract

| Port | Source | Why |
| --- | --- | --- |
| `22/tcp` | `ssh_allowed_cidr` | administration and the deploy path |
| `8200/tcp` (`api_port`) | `api_allowed_cidr` | the secrets API — **must not be `0.0.0.0/0`**, enforced by validation |

Nothing else is open. There is no 80/443 rule because this host serves no web UI.
The `api_allowed_cidr != 0.0.0.0/0` check lives in both the root and module
variable definitions, so a permissive tfvars edit cannot silently open it.

**Zero-exposure alternative:** set `api_allowed_cidr` to a single address you
control *and* leave the container bound to loopback (`SECRETSD_BIND_ADDRESS=127.0.0.1`),
then reach the API through `ssh -L 8200:127.0.0.1:8200`. In that mode the 8200
rule is never exercised; it exists so the documented contract matches what a
operator can actually do.

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars   # gitignored; fill in the tenancy
tofu init
tofu fmt -recursive -check
tofu validate
tofu plan      # expect: Plan: 6 to add, 0 to change, 0 to destroy
```

`tofu apply` is a Stage 5 action, not part of this stage's verification.

## What is deliberately **not** in state

- the master key, root token or any `.env` value — keys are generated on the host;
- the SSH private key — only the public key enters instance metadata;
- application secrets of any kind. `terraform.tfstate` holds resource identifiers,
  and nothing in this configuration puts a credential into a resource attribute.

Cloud-init is rendered from a template that receives only the project name, the
API port, the install directory and the repository URL. Instance user-data is
readable from the metadata service by anything on the host, so treating it as a
safe channel for secrets would be a design error.

## Porting to AWS

| OCI | AWS |
| --- | --- |
| `oci_core_vcn` | `aws_vpc` |
| `oci_core_internet_gateway` | `aws_internet_gateway` |
| `oci_core_route_table` | `aws_route_table` + `aws_route` |
| `oci_core_security_list` | `aws_security_group` + `aws_vpc_security_group_ingress_rule` |
| `oci_core_subnet` | `aws_subnet` |
| `oci_core_instance` + `shape_config` | `aws_instance` (`t4g.small`, ARM, free tier) |
| `metadata.user_data` (base64) | `user_data` (plain) |

Keep the same two ingress rules on the security group, and the same module
outputs (`subnet_id`, `public_ip`). Nothing else changes.

## Porting to GCP

| OCI | GCP |
| --- | --- |
| `oci_core_vcn` | `google_compute_network` |
| `oci_core_internet_gateway` / route table | implicit default route |
| `oci_core_security_list` | `google_compute_firewall` (two rules, same CIDRs) |
| `oci_core_subnet` | `google_compute_subnetwork` |
| `oci_core_instance` | `google_compute_instance` (`e2-micro`, free tier in `us-central1`) |
| `metadata.user_data` | `metadata_startup_script` (drop the base64) |

GCP needs `network_interface { access_config {} }` for the public IP; the
`ingress_ports` output maps to the firewall `allow` blocks.

## Cost

Everything here sits inside the OCI Always Free envelope: A1.Flex 1 OCPU / 1 GB,
50 GB boot volume (200 GB free across the tenancy), and egress far below the
10 TB/month allowance. Effective monthly cost: **$0**.
