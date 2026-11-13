# Secure Secrets Management Sandbox

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![AES-256-GCM](https://img.shields.io/badge/crypto-AES--256--GCM-informational)
![Docker](https://img.shields.io/badge/Docker-read--only%20%2B%20cap__drop%20ALL-2496ED?logo=docker&logoColor=white)
![OpenTofu](https://img.shields.io/badge/IaC-OpenTofu%201.13-844FBA)
![Tests](https://img.shields.io/badge/smoke-25%2F25%20passing-brightgreen)
![Unit](https://img.shields.io/badge/unit-40%20tests-brightgreen)
![Verified on OCI](https://img.shields.io/badge/certified-OCI%20(Always%20Free)-F80000)

A small, auditable secrets service: store credentials encrypted at rest, hand
them out under scoped bearer tokens, rotate the master key without ever
decrypting a value, and keep a value-free audit trail. It runs in a single
hardened container on a 1 OCPU / 1 GB instance.

It is deliberately **not** a KMS or HashiCorp Vault. It is envelope encryption
you can read end to end in an afternoon — about 1,140 lines of Python, one
vault file, one master key.

---

## 📋 Overview

| | |
| --- | --- |
| **Problem** | Credentials end up in `.env` files, CI variables and shell history, with no rotation story and no audit trail |
| **Approach** | One service owns the ciphertext; clients hold only bearer tokens; the host never needs the plaintext at rest |
| **Cryptography** | AES-256-GCM envelope encryption: a fresh 32-byte data key per secret version, wrapped by a master key; the secret name is bound as associated data |
| **Authorization** | SHA-256 token digests in a reviewable TOML file, capabilities (`read`/`write`/`delete`/`list`/`rotate`) scoped by segment-aware path prefix |
| **Operations** | Read-only container, non-root uid, all capabilities dropped, 128 MiB cap, single-command OpenTofu deploy, `0600` vault and audit file |
| **Certified on** | Oracle Cloud Infrastructure (`eu-frankfurt-1`), Always Free / trial credits |
| **Measured footprint** | ~19 MiB RSS, ~52 ms per authenticated read, 224 MB image |

### Features

- **Envelope encryption** — per-version DEKs, master key only wraps them.
- **Name binding** — a ciphertext moved to another name fails to authenticate.
- **Master-key rotation** — re-wraps DEKs; values are never decrypted, so an
  interrupted rotation cannot leak plaintext.
- **Scoped tokens** — hash-only policy file, segment-aware prefixes
  (`app/ci` never matches `app/ci-tokens`), no tokens in Git.
- **Versioning** — overwrites increment a version, first `created_at` preserved.
- **Atomic persistence** — temp file + `fsync` + rename; `0600`/`0700` modes.
- **Value-free logging** — access log has method/path/status/duration; audit log
  has actor/action/name/version; neither ever holds a secret. Asserted by tests.
- **Operator CLI** (`vaultctl`) — put/get/list/rm/export/status/rotate; refuses
  `--value` because shell history is not a secret store.
- **Cloud-agnostic IaC** — OpenTofu modules for OCI with documented AWS/GCP
  mappings; VCN, subnet, gateway, route table, security list, compute.

---

## 🏗️ Architecture

```text
        [ Clients / Apps ]
        CI jobs · services · operators · vaultctl
                 │
                 │  Authorization: Bearer <token>
                 │  (plain HTTP — terminate TLS in front, or use an SSH tunnel)
                 ▼
      ( Encrypted Payload / Token )
        {"value": "…"} ≤ 64 KiB · token hash compared in constant time
                 │
                 ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ [ Secrets Management API ]            :8200  /v1/secrets     │
   │                                                              │
   │  /healthz  /readyz  /v1/status  /v1/secrets[/{name}]         │
   │  /v1/rotate                                                  │
   │        │                                                     │
   │        │  authenticate (SHA-256 of bearer token)            │
   │        │  authorize  (capability + segment-aware prefix)    │
   │        ▼                                                     │
   │ [ Cryptographic Engine & Access Policies ]                   │
   │                                                              │
   │   AES-256-GCM envelope                                       │
   │     DEK  := random 32 B per version                          │
   │     body := GCM(DEK, nonce, value, aad=name)                 │
   │     wrapped := GCM(KEK, nonce, DEK, aad=name)                │
   │   policies.toml: sha256 digests only, mounted read-only      │
   └───────────────────────────┬──────────────────────────────────┘
                               │  atomic write, fsync, rename
                               ▼
   ( Encrypted at Rest / OCI Compute Instance )
     /data/secrets.json   0600  ciphertext envelopes, names, versions
     /data/audit.log      0600  actor · action · name · version  (no values)
     container: read-only rootfs · uid 10001 · cap_drop ALL · 128 MiB
     host: Ubuntu 24.04 aarch64 · Docker 29 · security list 22/8200 ← operator /32
```

Request path in words: a client presents a token and an encrypted payload; the
API authenticates the token against the policy digests, authorizes the
capability on that path, and only then touches the cryptographic engine. The
engine unwraps the data key with the master key in memory, decrypts, and returns
the value. Nothing but ciphertext is ever written to disk.

---

## 🚀 Quick start

```bash
cp .env.example .env          # mock values: fine locally, replace anywhere real
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
docker compose --env-file .env -f docker/docker-compose.yml ps   # (healthy)
curl -s http://127.0.0.1:8200/healthz
```

### Initialize master keys

The master key (KEK) is 32 bytes, base64url-encoded to 43 characters. Generate
it **inside the image** so the tool matches the runtime:

```bash
docker run --rm cloudguard/secretsd:local --generate-key
# 43 characters — write it into .env (chmod 600) or a mounted key file
```

- `SECRETSD_MASTER_KEY` or `SECRETSD_MASTER_KEY_FILE` — exactly one.
- Losing it loses every secret; leaking it exposes the whole vault. Store it in
  a password manager or KMS, never in Git, Terraform state or user-data.
- Confirm which key a host is running without revealing it:
  `docker run --rm -e SECRETSD_MASTER_KEY=… -e SECRETSD_ROOT_TOKEN=check-only \
   cloudguard/secretsd:local --check` → `key_fingerprint=…`

### Manage access policies

Tokens never enter the repository; only their SHA-256 does.

```bash
printf '%s' 'the-token' | docker run --rm -i cloudguard/secretsd:local --hash-token
```

```toml
[[tokens]]
name = "ci-pipeline"
sha256 = "<64 hex characters>"      # from --hash-token
capabilities = ["read", "list"]
paths = ["app/ci", "shared/"]
```

The loader refuses plaintext `token` fields, unknown capabilities, malformed
digests and duplicate hashes. Prefixes are segment-aware. Reload with
`docker compose up -d`.

### Test the encryption/decryption loop

```bash
export SECRETSD_TOKEN=<root or scoped token>

printf '%s' '{"user":"app","password":"example"}' | \
  docker exec -i -e SECRETSD_TOKEN="$SECRETSD_TOKEN" cg-secretsd \
  python -m secretsd.cli put app/db/credentials
# app/db/credentials: version 1 (201)

docker exec -e SECRETSD_TOKEN="$SECRETSD_TOKEN" cg-secretsd \
  python -m secretsd.cli get app/db/credentials --raw
docker exec -e SECRETSD_TOKEN="$SECRETSD_TOKEN" cg-secretsd python -m secretsd.cli list
```

Render a `0600` env file for a consumer (refuses multiline values, which would
corrupt a `.env`; use `--format json` for those):

```bash
docker exec -e SECRETSD_TOKEN="$SECRETSD_TOKEN" cg-secretsd \
  python -m secretsd.cli export --format env --prefix app/ci --out /tmp/app.env
```

Verify encryption at rest yourself:

```bash
docker exec -i cg-secretsd python - <<'PY'
import json
raw = open("/data/secrets.json").read()
print("plaintext present:", "example" in raw)   # expect False
print("envelopes:", sorted(json.loads(raw)["records"]))
PY
```

Full suites:

```bash
PYTHONPATH=src python -m unittest discover -s tests          # 40 tests
SECRETSD_ROOT_TOKEN=… SECRETSD_APP_TOKEN=… bash tests/smoke.sh # 25 assertions
```

---

## 🔌 API

JSON everywhere. `Authorization: Bearer <token>` on all but the probes. Bodies
capped at 64 KiB (rejected `413` before reading).

| Method | Path | Capability | Response |
| --- | --- | --- | --- |
| `GET` | `/healthz` | — | `{"status":"ok"}` |
| `GET` | `/readyz` | — | `200` when the vault opened, `503` otherwise |
| `GET` | `/v1/status` | `list` | metadata, actors, key fingerprint |
| `GET` | `/v1/secrets` | `list` | names, versions, timestamps (no values) |
| `PUT` | `/v1/secrets/{name}` | `write` | `201` `{"name","version"}` |
| `GET` | `/v1/secrets/{name}` | `read` | `{"value","version","updated_at"}` |
| `DELETE` | `/v1/secrets/{name}` | `delete` | `{"deleted":true,"deleted_version":n}` |
| `POST` | `/v1/rotate` | `rotate` | `{"rotated":n}` — disabled unless opted in |

Errors: `{"error":"code","message":"…"}`. `401` bad/absent token, `403`
insufficient capability, `404` unknown secret, `405` wrong method, `400` invalid
name/JSON/value, `413` oversized body, `500 crypto_failure` when the master key
does not match the vault.

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRETSD_MASTER_KEY` | — | base64url 32-byte KEK (or use `_FILE`) |
| `SECRETSD_MASTER_KEY_FILE` | — | read the KEK from a mounted file |
| `SECRETSD_ROOT_TOKEN` | — | bootstrap token with every capability |
| `SECRETSD_POLICY_FILE` | `/etc/secretsd/policies.toml` | hash-only policy file |
| `SECRETSD_DATA_DIR` | `/data` | vault + audit location |
| `SECRETSD_PORT` / `SECRETSD_BIND` | `8200` / `0.0.0.0` | listener |
| `SECRETSD_ALLOW_API_ROTATION` | `false` | enables `POST /v1/rotate` |

---

## 🛡️ Security model

**Envelope encryption.** Each version gets a fresh DEK and nonces. Rotation
re-wraps small blobs and never decrypts values.

**Name binding.** The name is associated data for both the value and the DEK, so
moving ciphertext between names fails authentication rather than silently
promoting a dev credential to production.

**Hash-only policies.** `policies.toml` holds digests, is safe to review, and is
mounted read-only. Tokens live only in the environment.

**Value-free logs.** Asserted by tests: grep either log for a stored value and it
is absent. The audit trail reveals secret *names*, which is why `audit.log` is
gitignored too.

**Hardened runtime.** `read_only: true`, `user 10001:10001`, `cap_drop: ALL`,
`no-new-privileges`, `pids_limit 64`, 128 MiB, tmpfs `/tmp`, healthcheck.

### What this does **not** protect against

| Threat | Reality |
| --- | --- |
| Host root reading the master key | The KEK is in the process environment; root can read it. Use a KMS or a tmpfs key file beyond a sandbox. |
| A compromised container | It can decrypt anything it can read and holds whatever token it was given. |
| Traffic interception | No TLS in the container. Terminate TLS in front or use an SSH tunnel. |
| Vault rollback | Restoring an older `secrets.json` is not detected; there is no signed revision history. |
| Multi-tenancy | None. One vault, one key, one trust domain. |

---

## ☁️ Cloud-Agnostic Portability Note

The container and the OpenTofu modules are **cloud-agnostic by design**. The
modules carry explicit mappings for AWS and GCP in their headers, and the service
itself depends on nothing but a Linux kernel, Docker and a writable `/data`.

> **Certification scope.** Final production verification and testing
> certification were performed **strictly on Oracle Cloud Infrastructure (OCI)**,
> using **trial credits** (plus the Always Free envelope). AWS and GCP are
> supported *ports*, not certified targets. This project is not "AWS-verified" or
> "GCP-verified" — those deployments have not been executed here.

### Migration tips — AWS

| OCI resource (implemented) | AWS equivalent |
| --- | --- |
| `oci_core_vcn` | `aws_vpc` |
| `oci_core_subnet` (public) | `aws_subnet` + route table association |
| `oci_core_internet_gateway` + route table | `aws_internet_gateway` + `aws_route` |
| `oci_core_security_list` (22, 8200) | `aws_security_group` ingress, same `/32` sources |
| `oci_core_instance` `VM.Standard.A1.Flex` | `aws_instance` `t4g.small` (ARM) or `t3.micro` (x86) |
| cloud-init user-data | same `cloud-init.yaml.tftpl`, unchanged |
| 50 GB boot volume | `root_block_device` gp3, 50 GB, encrypted |

- Keep ARM (`t4g`) to match the certified `aarch64` image; if you switch to
  `t3.micro`, rebuild the image (`docker build` does this automatically).
- Use `data "aws_ami"` with the Ubuntu 24.04 owner filter instead of an OCI
  image OCID; `cloud-init` installs Docker identically.
- Set `associate_public_ip_address = true` and attach an internet gateway; the
  AWS default VPC already has one.
- Budget for **egress**: the first 100 GB/month is free, then $0.09/GB, and a
  public IPv4 address is $0.005/hour.

### Migration tips — GCP

| OCI resource (implemented) | GCP equivalent |
| --- | --- |
| `oci_core_vcn` | `google_compute_network` |
| `oci_core_subnet` | `google_compute_subnetwork` |
| internet gateway + route table | implicit default route to the internet |
| `oci_core_security_list` | `google_compute_firewall` (ingress 22/8200) |
| `oci_core_instance` | `google_compute_instance` `e2-micro` (x86) or `t2a-standard-1` (ARM) |
| 50 GB boot volume | `boot_disk.initialize_params` pd-standard, 50 GB |

- `e2-micro` is x86: the image must be rebuilt for `amd64`, which the
  `Dockerfile` handles without changes.
- GCP has no security-list object; create two `google_compute_firewall` rules and
  set `source_ranges` to the operator `/32` — never `0.0.0.0/0`.
- `e2-micro` is Always Free only in `us-west1`, `us-central1` or `us-east1`, and
  only with **standard** persistent disk (balanced disks are billed).
- Premium-tier egress includes 200 GB/month free, then $0.12/GB; a static
  external IPv4 is $0.005/hour.

---

## 💰 Cross-Cloud Cost & Benchmark Estimation

Footprint priced: **1 vCPU, 1 GB RAM, 50 GB disk, containerized service, low
egress** (≈200 GB/month), 730-hour month, list prices read November 2026.
Regions: OCI `eu-frankfurt-1`, AWS `us-east-1`, GCP `us-central1`.

| Line item | OCI (Always Free / Trial) | AWS (t3.micro + EBS + egress) | GCP (e2-micro + PD + egress) |
| --- | --- | --- | --- |
| Compute (1 vCPU / 1 GB) | **$0** — A1.Flex within 2 OCPU / 12 GB allowance | $7.59 — `t3.micro` @ $0.0104/h | $6.13 — `e2-micro` @ $0.0084/h (free tier: 1 VM-month in us-west1/central1/east1) |
| Block storage (50 GB) | **$0** — within 200 GB allowance | $4.00 — gp3 @ $0.08/GB-mo | $2.00 — pd-standard @ $0.04/GB-mo (30 GB free ⇒ ~$0.80) |
| Public IPv4 | **$0** — included | $3.65 — $0.005/h | $3.65 — $0.005/h |
| Egress (200 GB/mo) | **$0** — 10 TB/month free | $9.00 — 100 GB free, then $0.09/GB | **$0** — 200 GB free (premium tier), then $0.12/GB |
| Trial credit | **$300 / 30 days** | up to $200 (new accounts) | **$300 / 90 days** |
| **Effective monthly** | **$0.00** | **≈ $15.24 + $9.00 egress ≈ $24.24** | **≈ $10.58**, or **$0** inside free tier |
| Always-free permanence | Yes (home region) | No — 12-month micro hours are gone | Yes, with strict region/disk rules |

Notes and caveats:

- Oracle **halved** the Always Free Ampere A1 allowance in 2026 to 2 OCPU /
  12 GB (1,500 OCPU-hours + 9,000 GB-hours). The tested 1 OCPU / 1 GB instance
  still fits, but a 4 OCPU / 24 GB plan no longer does.
- Beyond the free allowance, OCI A1 lists at roughly $0.01/OCPU-hour plus
  $0.0015/GB-hour — about **$8.40/month** for 1 OCPU / 1 GB, before storage.
- AWS no longer gives 750 free `t3.micro` hours to accounts whose 12-month
  window has passed; treat compute as billable unless the account is new.
- GCP's free tier covers **one** `e2-micro`, 30 GB **standard** disk and only
  **1 GB** of egress per month — the 200 GB egress allowance above is separate
  from the Compute free tier and applies to premium-tier DTO.
- Storage must be encrypted in all three clouds: enable EBS encryption (default
  since 2023), GCP default encryption, or OCI vault-managed keys. The vault file
  is already ciphertext, so this is defence in depth.
- Egress dominates at scale: at 1 TB/month the same service costs $0 on OCI,
  ~$83 on AWS and ~$96 on GCP. This is the single biggest reason the certified
  deployment lives on OCI.

### Benchmarks (measured on the tested deployment)

| Metric | Value | Where measured |
| --- | --- | --- |
| Image size | 224 MB (`aarch64`, `python:3.12-slim` + `cryptography`) | OCI host build |
| Cold start to healthy | ~2 s container, ~5 s healthcheck `start_period` | OCI host |
| Idle memory | 19.3 MiB / 128 MiB cap | OCI host, `docker stats` |
| CPU at idle | 0.01–0.02 % | both hosts |
| Authenticated read | ~52 ms average (100 sequential) | local Stage 4 |
| 100 reads, 10-way concurrency | 3.5 s wall | local Stage 4 |
| Smoke suite | 25/25 assertions | local + live |
| Unit suite | 40 tests (1 skipped on Windows) | local |
| Provisioning | 34 s instance, ~170 s cloud-init to Docker ready | OCI Stage 5 |
| Destroy | 6 resources, instance 1m4s | OCI Stage 6 |

---

## 🧱 Repository layout

```text
├── src/secretsd/            # crypto, store, policy, api, cli, __main__
├── configs/policies.toml    # token digests + capabilities (no tokens)
├── configs/schema/          # on-disk envelope schema
├── docker/docker-compose.yml# hardening, limits, healthcheck
├── terraform/               # OpenTofu: network + compute modules (OCI)
├── tests/                   # 40 unit tests + 25-assertion smoke suite
├── docs/                    # stage verification transcripts
├── AGENT_GUIDE.md           # verified execution playbook for coding agents
├── MANUAL_PREREQS.md        # operator checklist (keys, tokens, OCI, pre-flight)
└── Dockerfile               # python:3.12-slim, non-root, single dependency
```

---

## 🗺️ Roadmap and verification status

| Stage | Scope | State |
| --- | --- | --- |
| 1 | Scaffold, crypto core, API, policies, git boundary | ✅ 40 unit tests, 25 smoke |
| 2 | OCI infrastructure with OpenTofu | ✅ `validate` + `plan: 6 to add` |
| 3 | Operator runbook and agent guide | ✅ `AGENT_GUIDE.md` + `MANUAL_PREREQS.md` |
| 4 | Local drills: tamper, rotation, denial, load | ✅ `docs/stage-4-verification.txt` |
| 5 | Live OCI deployment and verification | ✅ 6 resources, 25/25 live, `docs/stage-5-verification.txt` |
| 6 | Teardown to zero billable resources | ✅ 6 destroyed, instance `TERMINATED`, `docs/stage-6-teardown.txt` |
| 7 | Security audit, README, cost model | ✅ `docs/stage-7-security-audit.txt` |
| 8 | Release and portfolio certification | ⬜ |

Every claim above is backed by a transcript in [`docs/`](docs/): what ran, what
it printed, and what remained unverified. Stages that were not executed in a
cloud are labelled local; the OCI deployment was real, and so was its teardown.
