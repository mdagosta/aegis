# Dev container

Aegis is developed in a Rust-only container on orpheus, copied from epiphyte's (whose
`docs/dev-containers.md` and `docs/adr/` explain the design). Same boundary: no credentials inside,
outbound HTTPS to an allowlist only, no sudo, and work leaves only through a git fetch reviewed on the Mac.

Differences from epiphyte's: one service (no postgres, nginx or mailpit), no published ports, no Node or
Python packages. The vault's Python client uses only the stdlib.

## The shape

| Piece | File | Notes |
|---|---|---|
| Image | `.devcontainer/Dockerfile` | Ubuntu 24.04, Rust (same version as `rust-toolchain.toml`), python3, Claude Code, herdr; dev user, no sudo |
| Service | `.devcontainer/compose.yaml` | Volumes: `repo`, `claude`, `cargo_registry`; read-only mounts of dotfiles and the SSH public key |
| Start | `.devcontainer/entrypoint.sh` | Root: firewall, Claude policy from dotfiles, volume ownership, then drops to the dev user |
| Firewall | `.devcontainer/firewall.sh`, `firewall-allowlist` | HTTPS to Claude, crates.io, rustup and GitHub only; fails closed |
| Setup | `.devcontainer/post-create.sh` | Dotfiles links, `cargo fetch`; piped in from the Mac's copy by `dev.sh up` |
| Getting in | `.devcontainer/sshd/aegis.conf` | `ssh aegis-dev` is `docker exec … sshd -i`; nothing listens |

## Daily use (on the Mac)

```
make dev-ssh-config  # once: Host aegis-dev in ~/.ssh/config
make dev-up          # build if needed, start, seed an empty repo volume, run setup
make dev-shell       # or: ssh aegis-dev, or herdr
make dev-push        # send a branch in (BRANCH=name; default the Mac's current branch)
git fetch aegis-dev && git log -p master..aegis-dev/master   # get work out: read it first
git merge aegis-dev/master && git push                       # then to GitHub, from the Mac
make dev-restart     # rerun the start: firewall re-resolved, Claude policy recopied
make dev-down        # stop; volumes are kept
```

- **Review before merging.** After a merge, `make dev-*` runs the merged `Makefile` and `.devcontainer/`
  files on the Mac. Read every diff there with extra care.
- **Edit the allowlist → rebuild** (`make dev-up`), not restart: the file is part of the image.
- **Bump Rust in both places:** `rust-toolchain.toml` and the Dockerfile's `RUST_VERSION`, then rebuild.
- A rebuild ends every shell and agent in the container. Commit and fetch first.
- The machine-specific Claude file is `CLAUDE.aegis-dev.md` in the dotfiles, if you want one.

## Boundary checklist

Inside, as the dev user:

| Check | Command | Expect |
|---|---|---|
| No root | `sudo -n true`; `grep -E 'Cap(Eff\|Prm\|Amb)\|NoNewPrivs' /proc/self/status` | sudo not found; caps all 0, NoNewPrivs 1 |
| Firewall can't be touched | `iptables -S` | permission denied |
| Unlisted host refused | `curl -m 5 https://example.com` | fails at once |
| Listed host works | `curl -sm 5 -o /dev/null -w '%{http_code}\n' https://index.crates.io/config.json` | 200 |
| Mac host refused | `curl -m 5 https://host.docker.internal` | refused |
| No Docker socket | `ls /var/run/docker.sock` | no such file |
| Mac mounts read-only | `grep host- /proc/mounts` | every line has `ro` |
| Root files | `ls -l /etc/claude-code/managed-settings.json /etc/claude-code/managed-settings.d/ /usr/local/bin/aegis-firewall` | owned by root |

From the Mac:

| Check | Command | Expect |
|---|---|---|
| Firewall came up | `docker compose -f .devcontainer/compose.yaml logs app \| grep firewall` | `firewall: up (N allowed addresses)` |
| No published ports | `docker compose -f .devcontainer/compose.yaml ps` | no ports |

Known gaps are the same as epiphyte's (shared CDN addresses, DNS, the startup window, prefix-rule
managed settings).
