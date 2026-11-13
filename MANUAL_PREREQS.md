# MANUAL_PREREQS — operator setup checklist

Everything a human must prepare **before** running this project's deployment
scripts. Work top to bottom; each step has a verification command, and a step is
only done when its check passes.

This project stores credentials, so the checklist is deliberately strict about
where values live: secrets go in `.env` (gitignored) or a mounted key file, and
**never** into Git, Terraform state, instance user-data or a chat message.

---

## 0. What you need

- [ ] Docker 29+ with Compose v2/v5
- [ ] OpenTofu 1.6+ (`tofu --version`) — Terraform 1.6+ also works
- [ ] An OCI account (Always Free or trial credits) with permission to create VCN
      and compute resources in one compartment
- [ ] An SSH key pair (`ssh-keygen -t ed25519 -C "you@example.com"`)
- [ ] Your public egress IP: `curl -s https://ifconfig.me`
- [ ] ~10 minutes, and a password manager for the master key

> **Certification scope:** the IaC and container configuration are cloud-agnostic
> and contain AWS/GCP mappings. **Final production verification and testing
> certification were performed strictly on Oracle Cloud Infrastructure (OCI),
> using trial credits / the Always Free envelope.** AWS and GCP are ports, not
> certified targets — do not claim otherwise in a portfolio write-up.

---

## 1. Clone and confirm the boundary

- [ ] Clone the repository and enter it:

```bash
git clone https://github.com/kaveh8866/Secure-Secrets-Management-Sandbox.git
cd Secure-Secrets-Management-Sandbox
```

- [ ] Confirm the sensitive paths are ignored **before** creating any:

```bash
git check-ignore -v .env terraform/terraform.tfvars data/secrets.json
```

Expected: three matches (`.env`, `*.tfvars`, `data/`). If any line is missing,
stop — fix `.gitignore` first.

---

## 2. Generate the master key

The master key is the only thing that can decrypt the vault. Treat it like a
root credential.

- [ ] Generate one (43 characters, base64url):

```bash
docker build -t cloudguard/secretsd:local .
docker run --rm cloudguard/secretsd:local --generate-key
```

- [ ] Store it **outside Git** — password manager, OS keychain, or a secrets
      manager. Keep a backup: without it, the vault is unrecoverable by design.
- [ ] Note its **fingerprint** (safe to share) once the service starts; use it to
      confirm which key a host is running:

```bash
docker run --rm -e SECRETSD_MASTER_KEY='<key>' \
  -e SECRETSD_ROOT_TOKEN=check-only-token-value \
  cloudguard/secretsd:local --check
# configuration ok: secrets=0 key_fingerprint=<12 hex> actors=1
```

Do **not**: commit it, paste it into Terraform, put it in cloud-init/user-data, or
include it in a screenshot.

---

## 3. Define access tokens

Tokens are bearer credentials. Only their **SHA-256** goes into the repository.

- [ ] Choose a root/bootstrapping token (≥ 24 random characters; a password
      manager generator is fine).
- [ ] Choose per-consumer tokens (e.g. one for CI, one for a service).
- [ ] Hash each one:

```bash
printf '%s' 'the-token' | docker run --rm -i cloudguard/secretsd:local --hash-token
# 64 hex characters — this is what goes into configs/policies.toml
```

- [ ] Add a `[[tokens]]` entry per consumer in `configs/policies.toml`:

```toml
[[tokens]]
name = "ci-pipeline"
sha256 = "<64 hex characters>"
capabilities = ["read", "list"]
paths = ["app/ci", "shared/"]
```

Rules the loader enforces (it refuses to start otherwise): no plaintext `token`
field, no unknown capability, no duplicate hashes, valid 64-char digest.

- [ ] Least privilege: give `read`/`list` unless the consumer must write. Prefixes
      are segment-aware — `app/ci` grants `app/ci/github` but **not** `app/ci-tokens`.

---

## 4. Populate `.env` securely

- [ ] Create it from the template:

```bash
cp -n .env.example .env
chmod 600 .env
```

- [ ] Fill in these values:

| Key | Required | Value |
| --- | --- | --- |
| `SECRETSD_MASTER_KEY` | yes | the key from §2, or use `SECRETSD_MASTER_KEY_FILE` instead |
| `SECRETSD_ROOT_TOKEN` | yes | the root token from §3 |
| `SECRETSD_BIND_ADDRESS` | yes | `127.0.0.1` locally; `0.0.0.0` on the instance **only** if the security list restricts 8200 |
| `SECRETSD_HOST_PORT` | yes | `8200` |
| `SECRETSD_ALLOW_API_ROTATION` | yes | `false` (raise only while running the rotation drill) |
| `TZ` | no | `UTC` |

- [ ] Never use `--value` on the CLI or `-e VAR=secret` on a command line: both
      end up in shell history and `ps`. The CLI refuses `--value` for this reason.

- [ ] Optional: mount a key file instead of an environment variable

```bash
install -m 600 /dev/null /run/secrets/secretsd-master-key
# write the key into that file, then in .env:
#   SECRETSD_MASTER_KEY_FILE=/run/secrets/secretsd-master-key
```

---

## 5. Prepare OCI credentials

Terraform authenticates with an API key, not with your console password.

- [ ] Create or reuse an API key in OCI: **Profile → API keys → Add API key**.
      OCI shows a config snippet; save the private key **outside this repository**
      (e.g. `~/.oci/oci_api_key.pem`, mode 600).
- [ ] Ensure `~/.oci/config` has a profile:

```ini
[DEFAULT]
user=<your user OCID>
fingerprint=<aa:bb:...>
tenancy=<your tenancy OCID>
region=eu-frankfurt-1
key_file=~/.oci/oci_api_key.pem
```

- [ ] Confirm the profile works (prints JSON, no secrets):

```bash
oci iam region list --profile DEFAULT --output table
# or, without the CLI:
openssl rsa -in ~/.oci/oci_api_key.pem -check -noout
```

- [ ] Copy the Terraform template and fill it in:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
chmod 600 terraform.tfvars
```

| Variable | What to put |
| --- | --- |
| `tenancy_ocid`, `compartment_ocid` | from the OCI console (identifiers, not secrets) |
| `region` | e.g. `eu-frankfurt-1` |
| `config_file_profile` | `DEFAULT` (leave inline key fields commented out) |
| `ssh_public_key` | **public** key content — `cat ~/.ssh/id_ed25519.pub` |
| `ssh_allowed_cidr` | your IP /32 from `curl -s https://ifconfig.me` |
| `api_allowed_cidr` | your IP /32 (or VPN range). **Never `0.0.0.0/0`** — validation rejects it |
| `availability_domain` | pin `…-AD-2` if AD-1 reports "Out of host capacity" |

- [ ] Confirm no private key slipped in:

```bash
grep -c "PRIVATE KEY" terraform/terraform.tfvars   # expect 0
```

---

## 6. Pre-flight checks

Run all of these before applying anything:

- [ ] `docker compose --env-file .env -f docker/docker-compose.yml config --quiet` → exit 0
- [ ] `docker build -t cloudguard/secretsd:local .` → exit 0
- [ ] `docker run --rm -e SECRETSD_MASTER_KEY="$KEY" -e SECRETSD_ROOT_TOKEN=check-only-token-value cloudguard/secretsd:local --check` → `configuration ok`
- [ ] `cd terraform && tofu init && tofu fmt -recursive -check && tofu validate` → `Success! The configuration is valid.`
- [ ] `tofu plan` → `Plan: 6 to add, 0 to change, 0 to destroy.`
- [ ] `git status --porcelain` shows only intentional files; no `.env`, `.tfvars`, `data/`

---

## 7. Local smoke test (before touching the cloud)

- [ ] Start the stack:

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
docker compose --env-file .env -f docker/docker-compose.yml ps    # (healthy)
```

- [ ] Run the contract test:

```bash
SECRETSD_ROOT_TOKEN="$SECRETSD_ROOT_TOKEN" bash tests/smoke.sh
# summary: 25 passed, 0 failed
```

- [ ] Confirm the vault is ciphertext with correct permissions:

```bash
docker exec cg-secretsd stat -c '%a %U:%G' /data/secrets.json      # 600 secretsd:secretsd
docker exec cg-secretsd tail -n 3 /data/audit.log                  # actions, no values
```

---

## 8. Deploy to OCI (Stage 5)

- [ ] `cd terraform && tofu apply` → 6 resources, ~35 s.
- [ ] Record the public IP: `tofu output -raw instance_public_ip`.
- [ ] SSH in: `ssh ubuntu@<ip>`; wait for cloud-init: `cloud-init status --wait`.
- [ ] Deploy on the host (see `AGENT_GUIDE.md` §13): clone, `.env`, build, up.
- [ ] Verify from the allowed network:

```bash
curl -s http://<ip>:8200/healthz
SECRETSD_URL=http://<ip>:8200 SECRETSD_TOKEN='<root>' bash tests/smoke.sh
```

- [ ] Confirm 8200 is **not** reachable from a network outside `api_allowed_cidr`
      (test from a phone hotspot or another host, expect a timeout).

---

## 9. Keep it healthy

- [ ] Rotate the root token by changing `SECRETSD_ROOT_TOKEN` and restarting.
- [ ] Rotate the master key with the drill in `AGENT_GUIDE.md` §11; keep the old
      key until a read verifies, then update `.env` and restart.
- [ ] Back up `/data/secrets.json` **and** the master key separately — one without
      the other is useless.
- [ ] Review `/data/audit.log` for unexpected actors or paths.
- [ ] Keep the host patched (unattended-upgrades is enabled by cloud-init).

---

## 10. Teardown

- [ ] `docker compose --env-file .env -f docker/docker-compose.yml down` (keeps the
      volume; add `-v` only when you intend to destroy the vault)
- [ ] `cd terraform && tofu destroy -auto-approve`
- [ ] `tofu state list` → empty
- [ ] Provider-side check: instance `TERMINATED`, no VCN remains
- [ ] Only then delete local state files; keep `terraform.tfvars` for a redeploy

---

## 11. Do not

| Never | Because |
| --- | --- |
| commit `.env` or `terraform.tfvars` | they hold the master key and tenancy identifiers |
| put the master key in Terraform, cloud-init or outputs | state and user-data are copied, cached and readable |
| open 8200 to `0.0.0.0/0` | this port hands out credentials; validation refuses it |
| add 80/443 "to check quickly" | no web UI exists; extra ingress is pure attack surface |
| paste a token hash from a public source | a public hash is a public token |
| delete the volume to "reset" | it destroys every secret; restore the key instead |
| trust a green `tofu validate` as deployment proof | it proves syntax, not a running host |
