# Secure Secrets Management Sandbox

A containerised secrets service for storing, encrypting, rotating and injecting
credentials — built to run on a 1 OCPU / 1 GB Always Free instance, with a
security model that assumes the host is not to be trusted with plaintext at rest.

**Status: Stage 4 complete — the local test matrix is green; nothing is deployed.**
Storage/retrieval, access control, at-rest encryption, audit trails, tamper
detection, wrong-key failure and low-spec load are all verified locally: 25/25
smoke assertions, 40 unit tests, one flipped ciphertext byte rejected with
`crypto_failure`. Evidence:
[`docs/stage-4-verification.txt`](docs/stage-4-verification.txt) (plus
[stage 1](docs/stage-1-verification.txt) and [stage 2](docs/stage-2-verification.txt)).
`tofu apply` remains a Stage 5 action.

---

## What it does

| Capability | How |
| --- | --- |
| Encrypt secrets | AES-256-GCM, one data key per secret version, wrapped by a master key (envelope encryption) |
| Store them | single JSON vault of ciphertext, atomic writes, mode `0600`, never `git`-tracked |
| Rotate | master-key rotation re-wraps data keys; values never leave their sealed form |
| Authorise | bearer tokens verified against SHA-256 hashes in `configs/policies.toml`, scoped by path prefix |
| Inject | `vaultctl export` renders a `0600` env file for a consumer process |
| Audit | append-only JSONL of who touched what — names and versions, never values |

### What it deliberately is **not**

- not a PKI, not a KMS, not HashiCorp Vault. It is a small, auditable envelope
  encryption service you can read end to end in an afternoon.
- not highly available: one node, one file, one key.
- not multi-tenant: the trust boundary is the container, and every tenant that
  can reach port 8200 shares it.

## Architecture

```text
   [ operator / CI ]                         [ consumer service ]
          │                                          │
          │  bearer token                            │  vaultctl export
          ▼                                          ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  container: cg-secretsd   (uid 10001, read-only rootfs)      │
   │                                                              │
   │   HTTP API :8200 ──► policy engine ──► SecretStore           │
   │   (stdlib)           sha256 tokens      │                    │
   │   vaultctl CLI        path-scoped       ▼                    │
   │                                    AES-256-GCM envelopes     │
   │                                    DEK per version,          │
   │                                    wrapped by master key     │
   └──────────────────────────────────┬───────────────────────────┘
                                      │
                          ┌───────────▼───────────┐
                          │ /data (named volume)  │
                          │ secrets.json  0600    │
                          │ audit.log     0600    │
                          └───────────────────────┘
```

The master key lives in the environment (or a mounted key file), never in the
volume. That separation is the point: a stolen volume is a file of ciphertext.

## Repository layout

```text
.
├── Dockerfile                     # runtime image (root: build context + audit)
├── .dockerignore
├── .env.example                   # placeholders only
├── .gitignore                     # zero-leak boundary
├── docker/
│   ├── docker-compose.yml         # hardened, low-spec service definition
│   └── README.md                  # what each runtime flag blocks
├── src/
│   ├── requirements.txt           # cryptography, pinned
│   └── secretsd/
│       ├── crypto.py              # envelope encryption + rotation
│       ├── store.py               # encrypted vault, atomic writes, audit log
│       ├── policy.py              # hash-only tokens, path scoping
│       ├── api.py                 # HTTP surface
│       ├── cli.py                 # vaultctl
│       └── __main__.py            # configuration + entrypoint
├── AGENT_GUIDE.md                 # agent playbook: build, test, rotate, inspect
├── MANUAL_PREREQS.md              # human checklist: keys, tokens, OCI, pre-flight
├── configs/
│   ├── policies.toml              # sample tokens (hashes) and capabilities
│   ├── schema/secret.schema.json  # on-disk record schema
│   └── samples/                   # illustrative envelope
├── terraform/                     # OCI VCN + A1.Flex; modules/network, modules/compute
├── tests/                         # unit tests (stdlib unittest)
└── docs/                          # verification transcripts
```

## Quick start

```bash
cp .env.example .env          # mock values: fine locally, replace anywhere real
docker compose --env-file .env -f docker/docker-compose.yml up -d --build
docker compose --env-file .env -f docker/docker-compose.yml ps
curl -s http://127.0.0.1:8200/healthz
```

Store and read a secret:

```bash
export SECRETSD_URL=http://127.0.0.1:8200
export SECRETSD_TOKEN=cg_mock_root_token_change_me   # from .env

printf '%s' 'example-not-a-real-credential' | python -m secretsd.cli put app/ci/github_token
python -m secretsd.cli list
python -m secretsd.cli get app/ci/github_token --raw
```

Inside the container the CLI is available as a module:

```bash
docker compose --env-file .env -f docker/docker-compose.yml exec \
  -e SECRETSD_TOKEN="$SECRETSD_TOKEN" secretsd \
  python -m secretsd.cli status
```

Render an env file for a consumer (mode `0600`, refuses to overwrite):

```bash
python -m secretsd.cli export --format env --out ./app.env
```

## API

All endpoints are JSON. `Authorization: Bearer <token>` is required everywhere
except the two probes. Bodies are capped at 64 KiB.

| Method | Path | Capability | Response |
| --- | --- | --- | --- |
| `GET` | `/healthz` | — | `{"status":"ok"}` |
| `GET` | `/readyz` | — | `200` when the vault opened, `503` otherwise |
| `GET` | `/v1/status` | `list` | service metadata, actors, key fingerprint |
| `GET` | `/v1/secrets` | `list` | names, versions, timestamps (no values) |
| `PUT` | `/v1/secrets/{name}` | `write` | `201` `{"name","version"}` |
| `GET` | `/v1/secrets/{name}` | `read` | `{"value","version","updated_at"}` |
| `DELETE` | `/v1/secrets/{name}` | `delete` | `{"deleted":true,"deleted_version":n}` |
| `POST` | `/v1/rotate` | `rotate` | `{"rotated":n}` — disabled unless opted in |

Error shape is `{"error":"code","message":"..."}`. Wrong or absent token is
`401`, an insufficient capability is `403`, an unknown secret is `404`, and a
body over the cap is `413` before it is read.

## Configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `SECRETSD_MASTER_KEY` | yes* | base64url 32-byte KEK (`python -m secretsd --generate-key`) |
| `SECRETSD_MASTER_KEY_FILE` | yes* | alternative: read the KEK from a mounted file |
| `SECRETSD_ROOT_TOKEN` | recommended | bootstrap token with every capability |
| `SECRETSD_POLICY_FILE` | no | default `/etc/secretsd/policies.toml` |
| `SECRETSD_DATA_DIR` | no | default `/data` |
| `SECRETSD_PORT` / `SECRETSD_BIND` | no | default `8200` / `0.0.0.0` |
| `SECRETSD_ALLOW_API_ROTATION` | no | default `false`; rotation stays a host-side action |

\* exactly one of the two key sources.

## Security model

**Envelope encryption.** Each secret version gets a fresh 32-byte data key and
fresh nonces. The data key is encrypted with the master key. Rotation therefore
re-wraps small blobs and never decrypts the values — an interrupted rotation
cannot leave plaintext anywhere.

**Name binding.** The secret name is used as associated data for both the value
and the data key. Moving a ciphertext from `dev/api` to `prod/api` makes it fail
to authenticate instead of silently granting a dev credential production
privilege.

**Hash-only policy file.** `policies.toml` holds SHA-256 digests, so it is safe
to commit and review. Tokens live only in the environment. Prefix matching is
segment-aware (`app/ci` never matches `app/ci-tokens`).

**Value-free logs.** The access log records method, path, status, duration and
request id. The audit log records actor, action, secret name and version. Grep
either one for a known secret and it will not be there — that property is
asserted by a test.

### What this does **not** protect against

| Threat | Reality |
| --- | --- |
| Host root reading the master key | The KEK is in the process environment. Root can read it. Use a KMS or a key file on a tmpfs for anything beyond a sandbox. |
| A compromised container | It can decrypt anything it can already read, and it holds the root token if you gave it one. |
| Traffic interception | No TLS. Reach the API through an SSH tunnel or inside a private network. |
| Rollback of the vault file | Deleting `secrets.json` and restoring an older copy is not detected; there is no signed revision history. |
| Multi-tenant isolation | None. One vault, one master key, one trust domain. |

These are documented rather than implied — a secrets project that overstates its
guarantees is worse than one that lists its limits.

## Testing

```bash
docker run --rm -v "$PWD":/app -w /app python:3.12-slim \
  sh -c 'pip install --no-cache-dir -q -r src/requirements.txt && python -m unittest discover -s tests -v'
```

Unit tests cover: round-trip and tamper detection, ciphertext not containing the
plaintext, per-seal nonce uniqueness, name binding, rotation semantics, atomic
persistence, `0600` permissions, audit-log hygiene, and the full policy matcher.

## Roadmap

| Stage | Scope | State |
| --- | --- | --- |
| **1** | Scaffold, container, crypto core, API, policies, git boundary | ✅ this stage |
| 2 | OCI infrastructure with OpenTofu (VCN, A1.Flex, no public 8200) | ✅ validated — `tofu validate` + `plan: 6 to add` |
| 3 | Operator runbook and agent guide | ✅ complete — `AGENT_GUIDE.md` + `MANUAL_PREREQS.md`, commands verified |
| 4 | Local drills: tamper, rotation, policy denial, low-spec load | ✅ 25/25 smoke, tamper + wrong-key + load verified |
| 5 | Live deployment and verification over an SSH tunnel | ⬜ |
| 6 | Teardown to zero billable resources | ⬜ |
| 7 | Security audit, cost table, final docs | ⬜ |
| 8 | MIT license, publish, vault certification | ⬜ |

## License

MIT (added at Stage 8).
