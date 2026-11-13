# Container runtime configuration

The image is built from the **repository root** `Dockerfile`, because the build
context must include both `src/` and `configs/`. CloudGuard's portability audit
also reads a root-level `Dockerfile`, and every project in this portfolio keeps
the build definition there. `docker/` owns everything about *running* the image;
the root owns what goes *into* it.

## Files

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | hardened service definition, volume, healthcheck, log rotation |
| `../Dockerfile` | image: Python 3.12 slim, uid 10001, no build tools shipped |
| `../.dockerignore` | keeps `.env`, keys, Terraform state and tests out of the build context |

## Hardening flags and what each one actually stops

| Flag | Effect | Attack it blocks |
| --- | --- | --- |
| `read_only: true` | root filesystem immutable | dropping a payload or replacing a binary at runtime |
| `user: 10001:10001` | non-root process | privilege escalation via file ownership |
| `cap_drop: ALL` | no Linux capabilities | `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`, etc. |
| `no-new-privileges:true` | no setuid/setgid gain | setuid helper escalation |
| `pids_limit: 64` | process ceiling | fork bombs and thread exhaustion |
| `mem_limit: 128m` | memory ceiling | OOMing the 1 GB host |
| `cpus: 0.25` | CPU ceiling | starving co-tenants on a free-tier VM |
| `tmpfs /tmp` 16 MiB | ephemeral, size-capped | persistent staging of stolen data |
| json-file 10 MiB × 2 | bounded logs | disk-fill via log spam |

## Deliberate omissions

- **No AppArmor/seccomp profile is mounted.** Docker's built-in seccomp profile
  already denies `clone` with new namespaces, `mount`, `ptrace` and the rest of
  the escape primitives. A hand-written allow-list for CPython is long, easy to
  get wrong, and would be less reviewed than the default. If you need one,
  derive it from the default profile rather than writing it from scratch.
- **No 443 listener and no TLS.** This API is meant to be reached over an SSH
  tunnel or from inside the VCN. Terminating TLS on a single-tenant sandbox adds
  a certificate lifecycle for traffic that never leaves the private network.
- **No Docker socket.** The container cannot start, inspect or kill anything.

## Verifying the posture yourself

```bash
docker inspect cg-secretsd \
  --format 'readonly={{.HostConfig.ReadonlyRootfs}} user={{.Config.User}} caps={{.HostConfig.CapDrop}} pids={{.HostConfig.PidsLimit}} mem={{.HostConfig.Memory}}'

docker exec cg-secretsd id                     # uid=10001 gid=10001
docker exec cg-secretsd touch /etc/probe       # must fail: read-only filesystem
docker exec cg-secretsd sh -c 'command -v curl' # no shell tooling expected
```
