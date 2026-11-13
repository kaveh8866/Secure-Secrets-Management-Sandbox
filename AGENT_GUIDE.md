# AGENT_GUIDE — Secure Secrets Management Sandbox

Operational guide for an agent or engineer working on this repository. Every
command below was run against the Stage 1 scaffold; anything not yet verified is
marked as such.

---

## 1. Ground rules

1. **Never print a secret value.** Not in a report, not in a commit message, not
   in a chat reply. Report names, versions, lengths and fingerprints.
2. **Never commit** `.env`, `terraform.tfvars`, `data/`, `*.pem`, `*.key`, vault
   files or audit logs. The `.gitignore` covers all of them; verify with
   `git check-ignore -v <path>` rather than by eye.
3. **The master key is not a Terraform variable.** It is injected at runtime.
   Provisioning must never write it to state.
4. **Rotation is a re-wrap, not a re-encrypt.** Do not "improve" it by
   decrypting values; the whole point is that plaintext never appears.
5. **Port 8200 is never opened in a security list.** Reach it over SSH or from
   inside the VCN.

## 2. Repository map

| Path | Responsibility |
| --- | --- |
| `src/secretsd/crypto.py` | envelope encryption, key parsing, rotation primitive |
| `src/secretsd/store.py` | vault file, atomic writes, audit log, versions |
| `src/secretsd/policy.py` | token hashing, capability/path matching |
| `src/secretsd/api.py` | HTTP surface, auth, body limits, access log |
| `src/secretsd/cli.py` | `vaultctl` client |
| `src/secretsd/__main__.py` | env configuration, startup, signal handling |
| `configs/policies.toml` | token hashes and capabilities |
| `configs/schema/` | on-disk record schema |
| `docker/` | compose and runtime hardening |
| `terraform/` | reserved; Stage 2 |

## 3. Common commands

```bash
# unit tests (needs the wheel, so run inside a Python image)
docker run --rm -v "$PWD":/app -w /app python:3.12-slim \
  sh -c 'pip install --no-cache-dir -q -r src/requirements.txt && python -m unittest discover -s tests -v'

# build and start
cp -n .env.example .env
docker compose --env-file .env -f docker/docker-compose.yml up -d --build

# health and status
curl -s http://127.0.0.1:8200/healthz
SECRETSD_TOKEN="$SECRETSD_TOKEN" python -m secretsd.cli status

# generate a real master key (prints once; store it outside the repo)
python -m secretsd --generate-key

# hash a new token for configs/policies.toml
printf '%s' 'the-token' | python -m secretsd --hash-token

# validate configuration without serving
docker compose --env-file .env -f docker/docker-compose.yml run --rm secretsd --check
```

## 4. Verifying the security posture

```bash
docker inspect cg-secretsd --format 'readonly={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}} user={{.Config.User}} pids={{.HostConfig.PidsLimit}}'

# each of these must fail or return the expected value
docker exec cg-secretsd id
docker exec cg-secretsd touch /etc/probe          # Read-only file system
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8200/v1/secrets          # 401
curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer wrong' \
  http://127.0.0.1:8200/v1/secrets                                                 # 401
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $APP_TOKEN" \
  http://127.0.0.1:8200/v1/secrets/app/admin/root                                  # 403
```

## 5. Failure modes seen in practice

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Master key is a single repeated byte` | still using the mock key from `.env.example` | generate a real key |
| `Master key does not unwrap this secret` | wrong key after a restart | restore the previous key; do not delete the vault |
| `Policy configuration rejected: … plaintext 'token'` | someone pasted a token into `policies.toml` | store the sha256 instead |
| `401` on every call | token missing `Bearer ` prefix, or hash mismatch | re-derive with `--hash-token` |
| container exits immediately | policy file missing at `/etc/secretsd/policies.toml` | mount `configs/` read-only, or set `SECRETSD_POLICY_FILE` |
| `413` | value larger than 64 KiB | secrets are not blobs; store the reference, not the archive |

## 6. Stage status

| Stage | Status |
| --- | --- |
| 1 — scaffold, crypto core, API, policies | ✅ verified locally (see `docs/stage-1-verification.txt`) |
| 2 — OCI infrastructure | ✅ verified 2026-11-13 — validate + plan 6 to add (`docs/stage-2-verification.txt`) |
| 3 — operator docs | ✅ this guide |
| 4 — local drills | ⬜ |
| 5 — live deployment | ⬜ |
| 6 — teardown | ⬜ |
| 7 — audit and cost | ⬜ |
| 8 — release | ⬜ |

## 7. What "verified" means here

A passing unit test proves the code's contract. A passing `docker build` proves
the image assembles. Neither proves the service is deployed. Stage 1 claims
exactly this much and no more; live deployment is Stage 5.
