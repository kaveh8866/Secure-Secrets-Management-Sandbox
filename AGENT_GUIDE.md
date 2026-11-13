# AGENT_GUIDE — Secure Secrets Management Sandbox

Execution playbook for AI coding agents (Cursor, Claude Code, Windsurf, Codex)
working on this repository. Every command below was executed against this
project; anything not yet run is labelled **UNVERIFIED** rather than implied.

Read §1 before running anything. This is the one project in the portfolio where
a careless command can destroy the thing the project exists to protect.

---

## 1. Agent contract

### Hard rules

| Rule | Why |
| --- | --- |
| **Never print a secret value** — not in a report, commit message, chat reply or log line | The whole project is about not leaking credentials; the agent transcript is a leak surface too |
| **Never commit** `.env`, `terraform.tfvars`, `data/`, `*.pem`, `*.key`, `secrets.json`, `audit.log` | Verified with `git check-ignore -v <path>`, never by eye |
| **Never put a key in Terraform** — not a variable, not user-data, not an output | State is stored, copied and sometimes shared; a master key in state is a leaked key |
| **Never rotate by decrypting** | Rotation re-wraps data keys; plaintext must not appear during it |
| **Never widen ingress** to `0.0.0.0/0` for the API port | The variable validation refuses it; do not "temporarily" bypass it |
| **Port 8200 is not a web port** | No 80/443 rule exists on purpose. Do not add one to "test quickly" |

### Reporting rule

Report names, versions, lengths, timestamps and fingerprints. When you need to
prove a value round-trips, compare it inside the container and report
`match`/`mismatch` — not the value.

---

## 2. Repository map

| Path | Responsibility | Touch when |
| --- | --- | --- |
| `src/secretsd/crypto.py` | envelope encryption, key parsing, re-wrap | changing crypto parameters |
| `src/secretsd/store.py` | vault file, atomic writes, audit log, versions | changing persistence |
| `src/secretsd/policy.py` | token hashing, capability/path matching | changing authorization |
| `src/secretsd/api.py` | HTTP routes, auth, body limits, access log | adding an endpoint |
| `src/secretsd/cli.py` | `vaultctl` client | adding an operator command |
| `src/secretsd/__main__.py` | env configuration, startup, signals | adding configuration |
| `configs/policies.toml` | token hashes and capabilities | granting access |
| `configs/schema/` | on-disk record schema | changing the envelope |
| `docker/docker-compose.yml` | hardening, limits, healthcheck | changing runtime posture |
| `terraform/` | OCI VCN + instance | infrastructure changes |
| `tests/` | unit tests + HTTP smoke test | every behaviour change |

---

## 3. Phase 0 — preconditions

```bash
docker --version            # 29.x verified
docker compose version      # v5.5.1 verified
ss -ltn | grep 8200 || true # port must be free (compose publishes 127.0.0.1:8200)
```

If your shell is Git Bash on Windows, export `MSYS_NO_PATHCONV=1` before any
`docker run -v …` command; otherwise `host:container` specs are rewritten into
Windows paths and Docker rejects them with `invalid mount path: 'C'`. This was
hit and fixed during Stage 3.

---

## 4. Phase 1 — build

```bash
docker build -t cloudguard/secretsd:local .
```

Expected: exit 0, image ~199 MB, base `python:3.12-slim`. The build installs the
single pinned dependency (`cryptography==50.0.2`) and copies `src/` and
`configs/`. No compilers, no shell tooling beyond the slim base.

---

## 5. Phase 2 — master key lifecycle

The master key is a 32-byte value, base64url-encoded to 43 characters. It wraps
per-secret data keys; **losing it loses every secret**, and leaking it exposes
the vault file.

Generate one (verified):

```bash
docker run --rm cloudguard/secretsd:local --generate-key
# 43 characters, e.g. PXWWhsqX... (do not paste the output into a report)
```

Important: the image has an `ENTRYPOINT`, so the flag goes **directly after the
image name**. `docker run ... python -m secretsd --generate-key` fails with
`unrecognized arguments` — that mistake was found in this project's own docs and
fixed.

Store it:

```bash
# option A: write it into the local, gitignored .env
cp -n .env.example .env
${EDITOR:-vi} .env        # set SECRETSD_MASTER_KEY=<the generated value>

# option B: keep it in a password manager and export per shell session
export SECRETSD_MASTER_KEY='...'
```

Verify the service accepts it without starting a listener:

```bash
docker run --rm -e SECRETSD_MASTER_KEY="$SECRETSD_MASTER_KEY" \
  -e SECRETSD_ROOT_TOKEN=dummy-token-for-check-only \
  cloudguard/secretsd:local --check
# configuration ok: secrets=0 key_fingerprint=<12 hex> actors=1
```

`--check` prints the **fingerprint**, never the key. Use the fingerprint to
confirm you are running the key you think you are.

---

## 6. Phase 3 — start the stack

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
docker compose --env-file .env -f docker/docker-compose.yml ps
```

Expected status: `Up … (healthy)`. If it restarts in a loop, jump to §12 — do not
`docker compose down -v`, which deletes the vault volume.

---

## 7. Phase 4 — health probes

```bash
curl -s http://127.0.0.1:8200/healthz          # {"service":"secretsd","status":"ok","version":"0.1.0"}
curl -s http://127.0.0.1:8200/readyz           # {"secrets":N,"status":"ready"}
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8200/v1/secrets   # 401
```

`/healthz` is unauthenticated and proves the process is alive. `/readyz` proves
the vault opened — a process can be alive with a wrong master key, and then every
read returns `500 crypto_failure`. Check both.

---

## 8. Phase 5 — secret storage and retrieval loop

Everything below runs **inside** the container, so no host Python setup is needed.

```bash
export ROOT=cg_mock_root_token_change_me   # from .env; never commit the real one

# write (value via stdin, never as an argument)
printf '%s' 'example-not-a-real-credential' | \
  docker exec -i -e SECRETSD_TOKEN="$ROOT" cg-secretsd \
  python -m secretsd.cli put app/ci/github_token
# app/ci/github_token: version 1 (201)

# read
docker exec -e SECRETSD_TOKEN="$ROOT" cg-secretsd \
  python -m secretsd.cli get app/ci/github_token --raw

# overwrite -> version 2, created_at preserved
printf '%s' 'rotated-value' | docker exec -i -e SECRETSD_TOKEN="$ROOT" cg-secretsd \
  python -m secretsd.cli put app/ci/github_token

# list (names, versions, timestamps — no values)
docker exec -e SECRETSD_TOKEN="$ROOT" cg-secretsd python -m secretsd.cli list

# render an env file for a consumer (0600, refuses to overwrite)
docker exec -e SECRETSD_TOKEN="$ROOT" cg-secretsd \
  python -m secretsd.cli export --format env --prefix app/ci --out /tmp/app.env

# delete
docker exec -e SECRETSD_TOKEN="$ROOT" cg-secretsd python -m secretsd.cli rm app/ci/github_token
```

`--format env` refuses multiline values: a PEM block would otherwise split into
several bogus variables and produce a half-valid `.env`. Use `--format json` for
those, or `--prefix` to exclude them. A refused export leaves no file behind.

Raw HTTP equivalent:

```bash
curl -s -X PUT -H "Authorization: Bearer $ROOT" -H 'Content-Type: application/json' \
  -d '{"value":"example-not-a-real-credential"}' \
  http://127.0.0.1:8200/v1/secrets/app/ci/github_token
```

Bodies are capped at 64 KiB and rejected with `413` before they are read. The
value must be a JSON **string**; there is no binary payload support by design —
store a path or a pointer, not a tarball.

---

## 9. Phase 6 — access policy verification

The sample `configs/policies.toml` grants `ci-pipeline` read+list on `app/ci` and
`shared/`. Test that the restriction is real:

```bash
export APP=cg_mock_app_token_change_me
B=http://127.0.0.1:8200

curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $APP" $B/v1/secrets            # 200 (has list)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $APP" $B/v1/secrets/app/ci/x    # 200 or 404, never 403
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $APP" $B/v1/secrets/app/ci-tokens/x  # 403 (segment-aware)
curl -s -o /dev/null -w '%{http_code}\n' -X PUT -H "Authorization: Bearer $APP" \
  -H 'Content-Type: application/json' -d '{"value":"x"}' $B/v1/secrets/app/ci/other                 # 403 (no write)
```

Adding a token:

```bash
printf '%s' 'the-new-token' | docker run --rm -i cloudguard/secretsd:local --hash-token
# paste only the 64-char digest into configs/policies.toml
docker compose --env-file .env -f docker/docker-compose.yml up -d   # reload
```

The loader rejects a policy file that contains a plaintext `token` key, and
rejects duplicate hashes — both checks have fired during development.

Run the whole contract at once:

```bash
SECRETSD_ROOT_TOKEN="$ROOT" SECRETSD_APP_TOKEN="$APP" bash tests/smoke.sh
# summary: 25 passed, 0 failed
```

---

## 10. Phase 7 — inspecting encrypted state and audit logs

These are read-only commands; the root filesystem is immutable and `/data` is a
named volume.

```bash
# the vault, pretty-printed (ciphertext only)
docker exec cg-secretsd python -m json.tool /data/secrets.json | head -30

# prove no plaintext is at rest (run with a value you know)
docker exec cg-secretsd python - <<'PY'
import json
raw = open("/data/secrets.json").read()
doc = json.loads(raw)
print("records:", list(doc["records"]))
print("envelope keys:", sorted(next(iter(doc["records"].values()))["envelope"]))
print("plaintext present:", "THE-VALUE-YOU-STORE" in raw)
PY

# permissions: must be 600 secretsd:secretsd
docker exec cg-secretsd stat -c '%a %U:%G' /data/secrets.json /data/audit.log

# audit trail: actions, actors, names, versions — never values
docker exec cg-secretsd tail -n 10 /data/audit.log
docker exec cg-secretsd sh -c 'grep -c "\"action\": \"read\"" /data/audit.log'
```

Reading the envelope:

| Field | Meaning |
| --- | --- |
| `v` / `alg` | envelope version and `AES-256-GCM` |
| `name` | bound as associated data; a blob moved to another name will not open |
| `dek_wrapped` / `dek_nonce` | the per-secret data key, sealed with the master key |
| `nonce` / `ciphertext` | the value, sealed with the data key |

If `plaintext present` is `True`, stop and treat it as a critical defect.

---

## 11. Phase 8 — rotation drill (verified)

Rotation is **off by default** (`SECRETSD_ALLOW_API_ROTATION=false`). The drill
below runs on a throwaway volume so the real vault is never touched:

```bash
export MSYS_NO_PATHCONV=1
IMG=cloudguard/secretsd:local; VOL=p06-rotate-drill
docker volume create $VOL
K1=$(docker run --rm $IMG --generate-key)
K2=$(docker run --rm $IMG --generate-key)

docker run -d --name p06rotate --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true --user 10001:10001 \
  -v "$VOL:/data" -p 127.0.0.1:8299:8200 \
  -e SECRETSD_MASTER_KEY="$K1" -e SECRETSD_ROOT_TOKEN=rotation-drill-root-token \
  -e SECRETSD_ALLOW_API_ROTATION=true $IMG
sleep 4

H='Authorization: Bearer rotation-drill-root-token'
curl -s -X PUT -H "$H" -H 'Content-Type: application/json' \
  -d '{"value":"survives-rotation"}' http://127.0.0.1:8299/v1/secrets/app/rotate/me
curl -s -X POST -H "$H" -H 'Content-Type: application/json' \
  -d "{\"new_master_key\":\"$K2\"}" http://127.0.0.1:8299/v1/rotate
# {"rotated":1,...}
```

Measured result: `GET` returns `200` with the original value after restarting on
`K2`; restarting on `K1` returns `500 crypto_failure`. Observing that failure is
the point — it proves the old key is dead, not merely unused.

Cleanup:

```bash
docker rm -f p06rotate && docker volume rm $VOL
```

For a real rotation: stop the stack, run the drill's rotate call against the real
volume with `SECRETSD_ALLOW_API_ROTATION=true`, then **update `.env` to the new
key before restarting**, or every read fails. Keep the old key until a read
verifies.

---

## 12. Phase 9 — troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| container restarting, log `Two policies share the same token hash` | sample policy reuses the root token hash | give each policy its own token hash |
| log `Policy configuration rejected: … plaintext 'token'` | a token was pasted into `policies.toml` | store the sha256 |
| log `No master key configured` | `.env` not passed to compose | `--env-file .env` |
| `401` on every call | missing `Bearer ` prefix, or hash mismatch | re-derive with `--hash-token` |
| `500 crypto_failure` | wrong master key for this vault | restore the previous key; do not delete the volume |
| `413` | value over 64 KiB | store a reference instead |
| `touch: cannot touch '/etc/probe': Read-only file system` | expected hardening | nothing to fix |
| `invalid mount path: 'C'` | Git Bash path conversion | `MSYS_NO_PATHCONV=1` |
| `docker run … python -m secretsd` → `unrecognized arguments` | entrypoint already runs the module | drop the module part: `IMAGE --generate-key` |
| one-off helper script fails with `unrecognized arguments` | the entrypoint consumed your `python -c` | put `--entrypoint python` before the image name |
| `export` → `Refusing --format env: multiline value(s) …` | a secret contains newlines | `--format json`, or `--prefix` to exclude it |

---

## 13. Phase 10 — OCI deployment (Stage 5)

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # gitignored; operator fills it
tofu init && tofu fmt -recursive -check && tofu validate
tofu plan      # expect: Plan: 6 to add
tofu apply     # 6 resources, ~35 s
```

Measured on the Stage 5 run: apply finished in 34 s for the instance, 6 resources
total, cloud-init reached `status: done` after ~170 s (Docker 29.9.3 + Compose
v5.7.1), host is Ubuntu 24.04 aarch64 with 945 MB RAM.

Then on the host (`ssh ubuntu@$(tofu output -raw instance_public_ip)`). The remote
checkout is normally transferred rather than cloned while the GitHub repository is
unpublished, and **never** carries `.env` or `terraform.tfvars`:

```bash
# from the operator machine, secrets excluded
tar -czf - --exclude=.git --exclude=.env --exclude=terraform/terraform.tfvars \
  --exclude=terraform/.terraform --exclude='*.tfstate*' --exclude='*.tfplan' --exclude=data . \
  | ssh ubuntu@<ip> 'rm -rf ~/Secure-Secrets-Management-Sandbox && mkdir -p ~/Secure-Secrets-Management-Sandbox && tar -xzf - -C ~/Secure-Secrets-Management-Sandbox'

cd ~/Secure-Secrets-Management-Sandbox
docker build -t cloudguard/secretsd:local .
docker run --rm cloudguard/secretsd:local --generate-key   # write into .env (0600), never to a tracked file
printf '%s' 'a-strong-operator-token' | docker run --rm -i cloudguard/secretsd:local --hash-token
python3 - <<'PY'   # replace both mock digests in configs/policies.toml
PY
docker compose --env-file .env -f docker/docker-compose.yml up -d
```

Set `SECRETSD_BIND_ADDRESS=0.0.0.0` and `SECRETSD_HOST_PORT=8200` in `.env` only
when the security list grants `api_allowed_cidr` access. For zero exposure leave
the bind on loopback and use `ssh -L 8200:127.0.0.1:8200`.

Live verification, from the host (tokens read from `.env`, never printed):

```bash
SECRETSD_ROOT_TOKEN="$SECRETSD_ROOT_TOKEN" SECRETSD_APP_TOKEN="$SECRETSD_APP_TOKEN" bash tests/smoke.sh
curl -s http://127.0.0.1:8200/readyz
docker exec -i cg-secretsd python - <<'PY'   # records, modes, canary scan
PY
```

Teardown: `tofu destroy -auto-approve`, then confirm with `tofu state list`
(empty) and a provider-side check — the same discipline as Project 05. Measured:
state 10 entries -> 0, six resources destroyed (instance 1m4s), instance
`lifecycleState=TERMINATED`, every network object `404 NotAuthorizedOrNotFound`,
former public IP closed on 22 and 8200. Without the OCI CLI, signed GETs against
`iaas.<region>.oraclecloud.com` (HTTP Signature v1) give the same answer.

---

## 14. Portability and certification

The OpenTofu modules and the container are **cloud-agnostic**: AWS and GCP
mappings are documented in `terraform/README.md` and in every module header
(`aws_vpc` / `aws_security_group` / `aws_instance t4g`; `google_compute_network` /
`google_compute_firewall` / `e2-micro`).

**Final production verification and testing certification were performed strictly
on Oracle Cloud Infrastructure (OCI), using trial credits / the Always Free
envelope.** AWS and GCP are supported *ports*, not certified targets. Do not
describe this project as "AWS-verified" or "GCP-verified" anywhere — not in a
README, not in a commit message, not in a portfolio claim.

---

## 15. Exit criteria for any change

1. `docker build` succeeds.
2. Unit tests pass (40 tests, 1 skipped on Windows): `PYTHONPATH=src python -m unittest discover -s tests`.
3. `bash tests/smoke.sh` → `25 passed, 0 failed`.
4. `docker inspect` still shows `readonly=true`, `user=10001:10001`, `capdrop=[ALL]`.
5. Vault contains no plaintext (`plaintext present: False`).
6. `git status` clean, no `.env`/`tfvars`/state staged.
7. Portability audit still passes if the change touched Git-tracked files.

A change that breaks any of these is not done, regardless of how green the unit
tests look.

---

## 16. Stage status

| Stage | Status |
| --- | --- |
| 1 — scaffold, crypto core, API, policies | ✅ verified locally |
| 2 — OCI infrastructure | ✅ `tofu validate` + `plan: 6 to add` |
| 3 — agent guide + manual prerequisites (this document) | ✅ complete |
| 4 — local drills (tamper, rotation, denial, low-spec load) | ✅ complete — `docs/stage-4-verification.txt` |
| 5 — live OCI deployment | ✅ 6 resources, 25/25 live, `docs/stage-5-verification.txt` |
| 6 — teardown to zero | ✅ 6 destroyed, instance `TERMINATED`, `docs/stage-6-teardown.txt` |
| 7 — security audit and cost table | ⬜ |
| 8 — release and vault certification | ⬜ |
