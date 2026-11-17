# Aegis

> Started in epiphyte's `plans/aegis.md`; moved here 2026-11-13. "Dev containers (orpheus)" describes epiphyte's setup and is kept as the pattern aegis and other projects follow.

Aegis becomes epiphyte's systems layer: a secrets vault, infrastructure management for DigitalOcean and Cloudflare, a private admin UI, and a deploy/ops runner, written in Rust. It replaces `secrets.py`, `.env.local`, `etc/cloudflare/`, and running deploy targets by hand on the prod box.

Four parts, built in this order:
1. **aegis-vault**: the secrets daemon on each box (plus `aegis-vault-admin`, its CLI).
2. **aegis-infra**: DigitalOcean and Cloudflare from the Mac; puts every secret it creates into a vault. Also delivers dotfiles (`aegis-infra dotfiles <host>`).
3. **aegis-web**: the admin UI, over SSH only.
4. **aegis-runner**: allowlisted deploy and ops actions.

Status: Phase 2 (vault MVP) in progress, Nov 2026. The vault, its CLI and the Python client have a first
pass; `docs/vault.md` is the operator's view (API, storage, running it).

## Repo layout

```
Cargo.toml              workspace; unsafe_code forbidden everywhere
crates/aegis-vault/     lib + bins aegis-vault (daemon), aegis-vault-admin (CLI)
crates/aegis-infra/     later (Phase 4)
crates/aegis-web/       later (Phase 6)
crates/aegis-runner/    later (Phase 7)
clients/python/         aegis_vault.py, stdlib only; apps vendor a copy
etc/aegis/              example policy.toml
etc/systemd/            hardened units
etc/sysusers.d/         users and groups for the units
deny.toml               cargo-deny policy (make deny)
docs/plan.md            this file
docs/vault.md           aegis-vault: API, storage, running it
```

## Why

- Secrets live in a plaintext `secrets.py` (symlinked into the repo tree) and `.env.local`. Anything running as the developer user can read them, including AI tools trying to be helpful. Neither the human nor the AI should be reading that file.
- Prod and dev share icarus today, as the same user, so dev mistakes and prod credentials sit side by side.
- More epiphyte apps are coming. The Makefile's per-app copy-paste and hand-run deploys won't scale.

Goals, in priority order: secrets are never readable as files by humans or tools; nothing can reach prod except through one audited, authenticated path; boring and rock solid over clever.

## Decisions

- **Its own repo from the start.** The Rust code lives on `master` of `~/src/aegis`; the old Python aegis stays on the `rough-draft` branch, untouched. Portable: nothing epiphyte-specific in the code, all paths, users and scopes from config. epiphyte's vendored Python lib (`epiphyte/aegis/`) is unrelated old code that keeps its name; it gains a copy of `clients/python/aegis_vault.py`.
- **Unix sockets, no TCP.** The kernel reports the caller's uid on a Unix socket (`SO_PEERCRED`), so the OS user is the credential. No token file to steal, nothing for SSRF or browser DNS rebinding to reach.
- **Encrypted SQLite, not Postgres.** The Postgres password is itself a secret, so the vault can't depend on Postgres. Separate store also means the vault works when Postgres is down.
- **Write-only secrets UI.** Values can be set, replaced, rolled back, deleted. Never displayed. There is no reveal route anywhere in the admin API.
- **Admin UI reached only over SSH.** No public hostname, no nginx vhost, no Cloudflare entry. `aegis-web` listens on a Unix socket; `ssh -L` forwards a laptop port to it.
- **Server-rendered UI.** Rust templates (askama), Tailwind built against `webapp/lib/tokens.css` so it matches the design system, a little JS (htmx or plain) for live job logs. No npm packages shipped to the browser, so the admin plane stays out of the npm supply chain.
- **Unattended boot.** The vault starts on its own after reboot, master key via `systemd-creds`.
- **Dev moves to a container on orpheus.** One container setup per project. icarus becomes prod only.
- **Infra and secrets together, infra from the Mac.** aegis-infra manages DigitalOcean and Cloudflare with no Terraform, runs only from the Mac with tokens from 1Password, and puts every secret it creates straight into a vault.
- **Few dependencies.** Independence matters with supply-chain worms around: no cloud SDKs, no IaC frameworks, small pinned crates.

## Architecture

```
  laptop browser -> http://localhost:7443
      |  ssh -L 7443:/run/aegis-web/web.sock icarus
      v
  aegis-web   (user aegis)          UI, passkey login, job logs
      |  admin.sock: set / delete / rollback / list metadata
      |  runner.sock: run action X with typed params
      +-----------------------+
      v                       v
  aegis-vault                 aegis-runner  (user aegis-run, narrow sudoers)
  (user aegis-vault,          allowlisted actions only
   PrivateNetwork=yes)
      ^  read.sock: uid-checked, per scope
      |
  web_prod, epiphyte_prod, aegis-runner, future apps
```

Three processes, three Unix users. Compromise of any one gives limited power:

| Compromised | Can | Cannot |
|---|---|---|
| aegis-web | overwrite/delete secrets (sabotage), queue allowlisted jobs | read any secret value, run arbitrary commands |
| aegis-runner | run its allowlisted actions, read the scopes it's granted | read other scopes, edit secrets |
| an app (www-data) | read its own scopes | edit anything, read other apps' scopes |
| developer user | nothing on prod | read the store, fetch prod scopes |
| aegis-infra SSH key | store or generate secrets (write-only) | read any secret, run anything else on the box |

## aegis-vault

Small, few crates, `#![forbid(unsafe_code)]`. tokio + axum 0.8 over `UnixListener`, rusqlite, chacha20poly1305, zeroize. axum only carries bytes and peer credentials: each socket has one fallback handler, and the routes are a hand-written table of enums (`routes.rs`), so what each socket can do is one screen to review and test.

**Sockets** (in `/run/aegis-vault/`, its own systemd `RuntimeDirectory`; each daemon gets its own directory, because two units sharing one `RuntimeDirectory` delete it out from under each other on stop):
- `read.sock` - mode 0660, group `aegis-clients`. `GET /v1/scope/{name}` returns that scope as JSON if the caller's uid is allowed.
- `admin.sock` - mode 0660, group `aegis-admin`. Set, delete, list metadata, list versions, rollback, audit, plus `store` and `generate` for aegis-infra. No route returns a value.

File modes are the outer fence; the real check is the peer uid (`SO_PEERCRED`) against policy on every request, so a wrong group or mode can't open anything. A uid the policy doesn't know on a socket gets 403 for every request, malformed ones included, so it learns nothing about routes or names. The daemon gives each socket its group (`[sockets]` in the policy), so its user needs both groups (`SupplementaryGroups=` in the unit).

**Policy** (`/etc/aegis/policy.toml`, root-owned, example in `etc/aegis/`). User names resolve to uids at startup; restart after changing users or policy.
```toml
[admin]
full = ["aegis", "root"]        # aegis-web, and the break-glass CLI via sudo
write_only = ["aegis-infra"]    # store and generate only

[scope."epiphyte/prod"]
allow_users = ["www-data"]

[scope."cloudflare/deploy"]
allow_users = ["aegis-run"]
```
Root is allowed on `admin.sock` because root can already decrypt the store; it is not given read access to any scope by default.

Users and groups are read from `/etc/passwd` and `/etc/group`, not through `getpwnam`: no `unsafe`, and no NSS module (LDAP and the like) gets a say in who reads secrets. A policy that names an unknown user or group, has an unknown field, or is writable by group or others stops the daemon from starting. `aegis-vault check-policy` shows what a policy resolves to before a restart.

**Names:** scope `[a-z0-9._-]+` segments joined by `/` (max 128), key `[A-Za-z0-9._-]+` (max 128). Values are UTF-8 text up to 64 KiB (PEM certs fit; binary goes in base64).

**Admin API** (JSON over `admin.sock`):
- `GET /v1/scopes` - every scope and key: current version, fingerprint, set at/by. Deleted keys show as deleted.
- `GET /v1/scope/{scope}/key/{key}/versions` - version history, metadata only.
- `PUT /v1/scope/{scope}/key/{key}` `{"value": ...}` - set (new version).
- `DELETE /v1/scope/{scope}/key/{key}` - writes a tombstone version, so a delete can be rolled back like any other change.
- `POST /v1/scope/{scope}/key/{key}/rollback` `{"version": n}` - writes a new version with version n's value (re-encrypted, since the version is part of the associated data).
- `POST /v1/scope/{scope}/key/{key}/generate` `{"bytes": 32}` - random value, base64url, never returned.
- `GET /v1/audit?limit=n` - recent audit rows.
- `write_only` callers may only `PUT` (the plan's `store`) and `generate`, and only onto keys that don't exist yet or that they set last; everything else is 403.

**Storage** (`/var/lib/aegis-vault/vault.db`, owned by `aegis-vault`, 0600):
- `secret(scope, key, version, action, nonce, ciphertext, kek_id, fingerprint, rollback_of, created_at, created_by, created_by_uid)`. No `is_current`: the current version is the highest, since every change (set, generate, delete, rollback) adds a version. A tombstone is a row with no ciphertext.
- XChaCha20-Poly1305, random 24-byte nonce per row, associated data is scope, key and version (length-prefixed, so no separator can be forged) so ciphertext copied to another row fails to decrypt.
- Keys are derived from the master key with HKDF-SHA256: one for encryption, one for fingerprints. `kek_id` is a short id of the master key, so rotating means re-encrypting rows under a new one.
- A `meta` canary row is encrypted at first start; a wrong master key refuses to start instead of writing rows nobody can read.
- Old versions kept, so a bad edit is rolled back without anyone seeing a value.
- Fingerprint per value: short HMAC (separate key) shown in the UI to compare values without revealing them.
- Values in memory are `Zeroizing`, as far as the vault's own buffers go (hyper's and serde's internal buffers are out of reach). SQLite is synchronous: one connection behind a mutex, called through `spawn_blocking`.
- Each audit row is written in the same transaction as the change it records, so a change that can't be audited doesn't happen. Fetches likewise: no audit row, no values.

**Master key:** 32 random bytes as 64 hex characters. In prod, `systemd-creds encrypt` with the host key and `LoadCredentialEncrypted=aegis-master-key`; the daemon reads `$CREDENTIALS_DIRECTORY/aegis-master-key`. In dev (no systemd), `--master-key <file>` (must be 0600). `aegis-vault keygen --out <file>` makes one and refuses to overwrite. icarus has no TPM, so the key is protected by root-only `/var/lib/systemd/credential.secret`. Root on the box can decrypt; nothing else can, and the DB file alone (e.g. in a backup) is useless. Copy of the master key kept in 1Password.

**Audit log:** every request (fetches, writes, and refused or malformed ones), as rows in `vault.db` and lines in the journal: time, uid, pid, `/proc/pid/cmdline` (Linux), socket, action, scope, key, version, outcome. Never a value. No notifications: the audit page and the journal are where you look. Rows are kept forever for now (see Open questions).

**Hardening** (systemd unit, `etc/systemd/aegis-vault.service`, `Type=notify`: ready once both sockets exist): `User=aegis-vault`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `ReadWritePaths=/var/lib/aegis-vault`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `UMask=0077`, `LimitCORE=0`, `LoadCredentialEncrypted=` for the master key.

## Python client

- `clients/python/aegis_vault.py` here, copied into each app (epiphyte vendors it into `epiphyte/aegis/vault.py`): fetch a scope over `read.sock` with the stdlib (`http.client` on a Unix socket, no new dependency).
- Replace the `epiphyte/secrets.py` symlink with a module of a different name (e.g. `epiphyte/secret_store.py`) that fetches at startup and exposes the same `hostnames` and `apply_hostname()`. Callers in `web.py`, `epiphyte.py`, `config.py`, `frob.py`, `codebug/notecards.py` change only their import.
- Renaming also fixes a latent bug: `import secrets` currently shadows Python's stdlib `secrets` module for the whole process.
- Fetch once at startup, keep in memory, never write to disk. Vault down at startup = fail fast, supervisor retries.

## aegis-web

- Listens on `/run/aegis-web/web.sock` only. Access: `ssh -L 7443:/run/aegis-web/web.sock icarus`, then `http://localhost:7443`.
- Auth layer 1: your SSH key. Auth layer 2: passkey login (WebAuthn). `http://localhost` counts as a secure context, so passkeys work without TLS. Keep the local port fixed so the origin is stable. The passkey matters because other processes on the laptop (including dev containers) can reach a forwarded localhost port.
- Own sessions and credentials, stored in its own SQLite. Not tied to epiphyte member login.
- Pages:
  - **Secrets:** scopes, keys, fingerprints, last set/by, versions, recent fetchers. Set (paste into a password field, never echoed back), rollback, delete with two-step confirm.
  - **Jobs:** run an action, live log stream, history with git revision and who started it.
  - **Apps** (later): status of each app's processes, current and previous version, revert button.
  - **Audit:** filterable log.
- Small pages, little JS, so the SSH tunnel feels fast.

## aegis-runner

- Executes a fixed allowlist of actions with typed parameters, e.g. `deploy(app, env)`, `revert(app, env)`, `cloudflare(plan|apply)`, `nginx(diff|apply)`. No free-form arguments or shell strings from the web.
- One job at a time per target (lock). Logs persisted and streamed. Prod actions need a two-step confirm.
- Narrow sudoers for exactly what deploys need (`supervisorctl restart <program>`, `-u www-data` for release dirs), replacing the broad sudo deploys use today.
- Gets the `cloudflare/deploy` scope from the vault, which retires `.env.local` on icarus.
- Stage 1: actions call existing Make targets by name. The Makefile keeps working by hand.
- Stage 2: one declarative list of sites (hostnames, processes, ports, secrets scope) that generates supervisor, nginx and Cloudflare config, so every site deploys the same way. Design it as its own planned step when the next app arrives, not ad hoc.

## aegis-infra

Infrastructure as code for the little we run on DigitalOcean and Cloudflare, in the same Rust workspace as the vault. Infra and secrets belong together: most secrets are *created* by infra (database users, origin certificates, API tokens), so aegis-infra creates them and puts them straight into a vault. No human, terminal, file or AI session ever sees them. The internet-facing app then holds only what it needs to connect.

**Why not Terraform/OpenTofu:** huge, burdensome, a large dependency tree, and their state files hold secrets in plain text. We manage about a dozen resource types. A small reconciler that talks to two REST APIs directly is less code to trust than one provider plugin.

**Runs from the Mac host only.** Not the dev container (no prod credentials there), not icarus (a break-in on the internet-facing box must not get the keys to the whole cloud). Infra changes are rare and big, so a human at the keyboard is a feature.

**Credentials from 1Password at run time:** `op run --env-file=etc/infra/op.env -- aegis-infra plan`. `op.env` holds only `op://` references, so it's committed. Tokens exist only in that one process's environment, unlocked by Touch ID. Separate tokens: read-only for `pull`/`plan`, write for `apply`, each scoped as narrowly as the provider allows (DigitalOcean custom scopes, Cloudflare scoped tokens).

**Model:**
- Desired state is TOML in the repo (`etc/infra/`), no secrets in it.
- No state file. Live state is read from the APIs on every run; the diff is desired vs live.
- aegis only touches what it owns: DigitalOcean tag `aegis` and Cloudflare records/projects listed in config. Anything else is reported, never changed.

**Commands:**
- `pull` - snapshot live state into the repo for review and commit (read-only), as `make cloudflare-pull` does today.
- `plan` - show the diff.
- `apply` - show the plan, confirm, apply. Never deletes. Deletes need `apply --delete` plus typing the resource name.

**Scope** (grows only when needed):
- DigitalOcean: droplets with cloud-init (a new box installs aegis-vault and its users on first boot), firewalls, VPC, reserved IPs, SSH keys, managed Postgres databases, users and trusted sources.
- Cloudflare: DNS, Pages projects and domains, origin certificates, scoped API tokens, later Access/Tunnels if wanted. Ports `etc/cloudflare/` (its `test_cloudflare.py` is the spec); the Python tool stays until parity.

**Secrets born in the vault:**
- When apply creates a database user, the password DigitalOcean returns goes into the target box's vault. Same for an origin certificate's private key, or a short-lived scoped Cloudflare token for one deploy.
- Delivery: SSH as a dedicated `aegis-infra` user on the box, whose key has a forced command (`aegis-vault-admin --stdio`) that only speaks the admin protocol. That key can do nothing else.
- The vault's admin socket accepts `aegis-infra` for two write-only operations: `store` (a value the caller just received) and `generate` (vault makes a random value and never returns it).

**Dependencies:** a small blocking HTTP client with rustls (ureq), serde, toml. No cloud SDKs.

## aegis dotfiles

Every machine I work on gets the same home and the same Claude policy: the Mac, each dev container, and any server I SSH into or reach through herdr. (A descendant of homecast, a tool from long ago that copied home-directory dotfiles to a new host.)

**Two kinds of thing travel:**
- **Home:** `.bashrc`, `.emacs`, `.gitconfig`, `claude/CLAUDE.md` plus the host's `CLAUDE.<hostname>.md`, shared skills, the status line. Linked into `$HOME` (and the Claude config dir).
- **Machine policy:** Claude Code managed settings (`claude/managed-settings.d/`), installed root-owned into `/Library/Application Support/ClaudeCode/` (macOS) or `/etc/claude-code/` (Linux). Later, perhaps sshd and sudoers drop-ins.

**Two layers:**
1. **The installer lives in `~/src/dotfiles`**, next to the files it installs: one script for macOS and Linux, wrapped by the dotfiles Makefile (`make install`, `make install-claude-policy`). It links the home files and, when asked with sudo, installs the policy. The Mac, the dev containers (`post-create.sh` for home, the entrypoint for policy) and servers all call it, replacing today's three separate copies of that logic. Useful before any Rust exists.
2. **Delivery is aegis's:** `aegis-infra dotfiles <host>` pushes the dotfiles repo to the host over SSH (git, `updateInstead`, the same bridge as the dev containers) and runs the installer there. aegis-infra's cloud-init runs it at a new droplet's first boot, next to installing aegis-vault. Runs from the Mac host only, like the rest of aegis-infra.

**Rules:**
- Nothing secret in dotfiles. Machine-specific or secret-bearing shell settings stay in a real `~/.bashrc_<hostname>` outside the repo (as `~/.bashrc_orpheus` does); the dotfiles' git history is readable wherever it's installed.
- Policy is installed as root-owned copies, never links, so editing dotfiles changes nothing until a deliberate install.
- Prod (icarus) can get the home, but it isn't a place Claude agents run: the policy there is a backstop, not permission.
- Organization accounts with server-managed settings use those instead of the local policy (first-wins); `/status` shows which applies.

## Dev containers (orpheus)

All dev moves into a per-project Linux container on orpheus: fast local CPU, the same Linux layout as prod, and a boundary that keeps mistakes (human or AI) away from the Mac and from prod. icarus becomes prod only.

### Runtime

- OrbStack on orpheus (any Docker-compatible runtime works; nothing here depends on it). Set it to start at login: every service has `restart: unless-stopped`, so the container is back up whenever OrbStack is, and only `make dev-down` stops it.
- `compose.yaml`, driven by `.devcontainer/dev.sh`. No `devcontainer.json`: editor integrations (VS Code Dev Containers) forward the Mac's SSH agent and git credentials into the container by default.
- Images are native arm64. Release binaries for icarus are cross-compiled to x86_64 musl (cargo-zigbuild), no emulation.

### Services

- **app** - Ubuntu 24.04 to match icarus. Python + venv, Node, Rust, tmux, Claude Code, herdr. Runs as `mdagosta` (uid 1000, same home path as icarus, so config.py's `md` paths work) with **no sudo**: system changes go through the Dockerfile and a rebuild. No supervisor: run Tornado web and Hydra by hand with `./locals`, as today.
- **postgres** - same major version as the managed prod Postgres. One database per app database (codebug, shared by ourquest), schema from the normal migrations, seed data from a fixture script. Never a prod dump. The migrations replay from an empty database: a diff that repeats something an earlier diff already does must skip it (`IF NOT EXISTS`, `ON CONFLICT DO NOTHING`).
- **nginx** - shares `app`'s network namespace, so it proxies to Vite and Tornado on 127.0.0.1 like icarus.
- **mailpit** - also in `app`'s network namespace, listening on localhost:25, so the default SMTP settings deliver into it. Dev never sends real email.
- **aegis-vault** - sidecar once phase 2 exists, socket on a shared volume. Holds dev-only secrets; the store file never appears inside `app`. Before then, dev secrets come from `.devcontainer/secrets.dev.py`, copied to a volume and filled in by hand.

### Getting in: herdr and SSH

- herdr on the Mac attaches to agents and terminals in the container (`hc machine add epiphyte-dev`). Plain `ssh epiphyte-dev` works too. `make dev-shell` stays for a quick shell.
- `make dev-ssh-config` adds `Host epiphyte-dev` to the Mac's `~/.ssh/config`. Its ProxyCommand is `docker exec -i epiphyte-app-1 /usr/sbin/sshd -i`: sshd runs once per connection and never listens, so no port is open and only someone who can already run docker on the Mac gets in.
- sshd accepts only orpheus's public key (`~/.ssh/id_orpheus.pub`, mounted read-only), only as `mdagosta`, no passwords, no root, no agent forwarding (`.devcontainer/sshd/epiphyte.conf`). Host key checks are off for this one host: keys change on every rebuild and the connection never crosses a network.
- Agents and shells live as long as the container: a rebuild or `make dev-down` ends them.

### Hostnames and HTTPS

- Keep today's dev hostnames (`md.codebug.com`, `md.ourquest.net`) so Google sign-in origins and cookies keep working unchanged. The list lives in `.devcontainer/dev.sh`, with matching server blocks in `.devcontainer/nginx/dev-sites.conf`.
- `make dev-hosts` adds the names to the Mac's `/etc/hosts` (`HOSTS="md.ourquest.net"` for just some, while the others are still served from icarus).
- mkcert on the Mac (`make dev-certs`) makes a local CA and certs for the dev hostnames; the container's nginx proxies each to its Vite port (codebug 5173, ourquest 5175) and Tornado on 8088.
- Container nginx publishes 443 on the Mac's 127.0.0.1 only, not the LAN.

### The boundary

The container is there so that a mistake by Claude (or a human) - deleting a home directory, running a bad script - can't reach the Mac or prod. Credentials are only half of that. Anything the container can write that the Mac later runs is a way out, and so is the open network. Each hole and how it closes:

| Hole | Closed by |
|---|---|
| Repo bind-mounted read-write from the Mac: Claude can write `.git/hooks` (run by the Mac on commit), the `Makefile` and `dev.sh` (run by `make dev-*`), `compose.yaml` (could mount Mac directories in on the next `dev-up`) | Repo moves inside the container (below). Git is the only bridge. |
| Secrets in the repo: Cloudflare origin keys in `etc/nginx/ssl/` (and in git history) | Move to the vault; issue new keys, since the old ones stay in history. Same for every repo. |
| Open outbound network: anything readable can be sent out; the droplet, the DO database host and Mac services (`host.docker.internal`) are reachable, though nothing inside has credentials for them | Outbound firewall allowlist (step 9, done). It allows by IP, and CDN addresses are shared, so a deliberate leak could still use a shared address or DNS: a hostname-filtering proxy closes the first (step 11). |
| Unpacked extension built in the container runs in Chrome with access to logged-in sessions | Load it only in a separate dev Chrome profile. |

Already true: no private SSH keys or agent forwarding inside, no Docker socket, no sudo, no prod or Cloudflare credentials, dev database only.

### Files

- **The repo lives inside the container**, on the named volume `repo` at `~/src/epiphyte`, not bind-mounted from the Mac. Treat it like a VPS checkout: the virtualenv and `node_modules` are plain gitignored folders in it, rebuilt by `post-create.sh`. Worst case inside (everything deleted) loses only what wasn't committed and fetched yet.
- The Mac keeps its own checkout. It is the trusted one: `.devcontainer/` is run from it, and reviews and pushes to GitHub happen from it. Anything the container mounts from it is read-only: nginx config (`etc/nginx/conf.d/epiphyte.conf`, `dev-sites.conf`), certs, `postgres/init.sql`, the SSH public key, the dotfiles. Changes to those made inside take effect only after they're merged on the Mac and `make dev-up` runs again.
- Git is the bridge, over the same `epiphyte-dev` SSH entry (Mac remote `epiphyte-dev` → `epiphyte-dev:src/epiphyte`):
  - Seeding and updating the container: `make dev-push` (`BRANCH=name`, default the Mac's current branch). It adds the remote if missing, `git init`s an empty volume on that branch, sets `receive.denyCurrentBranch=updateInstead` inside, and pushes. A push to the checked-out branch updates the working tree, and is refused if it has uncommitted changes. `make dev-up` seeds only an empty volume; after that, pushes are explicit.
  - Getting work out: the Mac fetches (`git fetch epiphyte-dev`), reads `git log -p main..epiphyte-dev/main`, merges, pushes to GitHub. Push runs `git-receive-pack` inside, fetch runs `git-upload-pack` inside; neither runs anything from the container on the Mac, since hooks and git config don't travel. `dev-push` also sets `fetch.fsckObjects=true` in the Mac checkout, so malformed objects are rejected. The trust point is merging: after that, `make dev-*` runs the merged `Makefile`, `dev.sh` and `compose.yaml`. Review before merging.
- Git identity comes from the Mac's `.gitconfig` in the read-only dotfiles mount. Sign-off (`-s`) works as usual.
- Named volumes for the repo, dev GPG keys (at `~/.gnupg-epiphyte`, outside the repo so `git clean -x` can't reach them; `~/src/epiphyte/gpg`, the path config.py uses, links to it; not rebuildable), dev secrets and Claude Code's login and settings.
- The extension builds in the container; `dist/` is copied out to a folder on the Mac for Chrome to load (a dev profile, per the table above).
- Mac editors no longer see the files; VS Code can attach over Remote-SSH with the same `epiphyte-dev` entry.

### Inside vs outside

| Inside the container | Mac host only |
|---|---|
| working repo, builds, tests, dev DB, dev secrets, Claude, herdr agents | trusted checkout, `.devcontainer/`, git push to GitHub |
| | SSH keys, 1Password, browser |
| | SSH to icarus: aegis-web tunnel, prod deploys, aegis `make deploy` |
| | extension release signing (`key.pem`) |

- No prod credentials in the container, ever: no SSH key to icarus, no Cloudflare token, no prod DB access. The prod Postgres is a shared managed cluster, so dev must not hold credentials to it at all.
- Until aegis-runner exists, prod deploys stay as today: SSH from the Mac to icarus and run make there.
- Claude runs inside with an outbound firewall allowlist (Anthropic API, package registries, GitHub read, Google sign-in), following Claude Code's reference devcontainer. With the container as the boundary, Claude can run with fewer permission prompts.
- Claude inside may change `.devcontainer/` files in its own checkout; they only take effect after they're fetched to the Mac, reviewed and run there.

### Code review

- Review happens on orpheus, before anything reaches icarus. icarus only ever runs reviewed, committed code from `main`.
- Flow: work in the container, then Claude runs `/code-review` (and `/security-review` for anything touching auth, secrets, deploys or `.devcontainer/`) on the diff inside the container. Commit inside, fetch to the Mac, read the diff with your own tools there, merge, and push from the Mac host.
- One Claude session per checkout. Parallel sessions on the same working tree overwrite each other; if parallel work is needed, use a separate git worktree per session.

### Makefile and docs

- Container controls live in `.devcontainer/dev.sh` (certs, hosts, build, up, shell, down, ssh-config), wrapped by `make dev-*` on the Mac host; `make list` shows them all. Inside the container `uname` is Linux, so every make target runs; the Darwin guard stays for the Mac host.
- Rewrite CLAUDE.md "Dev hosts": orpheus container = all dev; orpheus host = trusted checkout, Chrome, git push, SSH; icarus = prod, changed only through aegis (or make over SSH until then).

### Other projects

- Same pattern per project. When the second project adopts it, pull the shared parts into a base image and reuse the aegis-vault sidecar image.

### Steps

1. Dockerfile, `compose.yaml`; `make build-python` and `make build-extension` pass inside. **Done.**
2. Postgres with migrations (**done**: all diffs replay from empty) and fixture data.
3. nginx, mkcert, `make dev-hosts`; Vite watch for each site behind its dev hostname. Google sign-in works. (Certs and `md.ourquest.net` done.)
4. Tornado web and Hydra from `./locals`; mail lands in mailpit.
5. herdr and `ssh epiphyte-dev` into the container. **Done.**
6. Repo inside the container: named volume `repo` (venv and `node_modules` volumes dropped), `make dev-push` seeds and updates it, `updateInstead`, Mac remote `epiphyte-dev`, `fetch.fsckObjects`. Git identity from the read-only dotfiles. Read-only mounts only from the Mac. `post-create.sh` handles a fresh clone (webapp `.env.development` from the example).
7. Extension: copy `dist/` out to the Mac, load in a dev Chrome profile.
8. Secrets out of the repo: Cloudflare origin keys to the vault (or 1Password until it exists), new keys issued.
9. Outbound firewall for the app container, following Claude Code's reference devcontainer. **Done:** `.devcontainer/firewall.sh` at every start (fails closed), HTTPS only to `.devcontainer/firewall-allowlist` plus GitHub, postgres, nothing else, with the allowlist re-resolved every half hour; `NET_ADMIN` for root only and `no-new-privileges`, and the root scripts use their own PATH; postgres on an internal network with its superuser refused from the network (otherwise `COPY ... PROGRAM` there would get around the firewall); Claude's auto-updater off (updates come by rebuild). The allowlist is by IP, so shared CDN addresses mean it narrows rather than seals; DNS still goes out through Docker's resolver.
10. Update CLAUDE.md. Stop dev on icarus: remove the dev nginx sites, dev env files and dev processes there. Last, point the `md.*` DNS records at 127.0.0.1 in `etc/cloudflare/config.py` (DNS-only, not proxied; `make cloudflare-plan`, then `cloudflare-apply`), so any Mac reaches its own container with no `/etc/hosts` edit. Only after icarus stops serving `md.*`, since the switch takes those sites off icarus at once. Networks with DNS rebind protection (some routers, Pi-hole, NextDNS) refuse public names that resolve to loopback; `make dev-hosts` stays as the fallback. Reaching the container from a phone is a separate, later choice (Tailscale, a Let's Encrypt cert via Cloudflare DNS).
11. Later: hostname-filtering egress proxy. A small proxy container is the app's only way out (the firewall allows just the proxy); it connects only to allowlisted hostnames, by name, so shared CDN addresses stop being a way around the list. Claude Code, npm, pip, git and curl use it through `HTTPS_PROXY`; anything that ignores the variable fails closed. DNS through Docker's resolver remains the one leak.

Open: managed Postgres major version (container uses 16); confirm Google sign-in's authorized origins already cover the dev hostnames.

## Build and deploy of aegis itself

- icarus is 1 CPU / 2 GB: too small to compile Rust comfortably. Build on orpheus (in the container), target `x86_64-unknown-linux-musl` for static binaries, ship to icarus.
- `make build-release` builds (cargo-zigbuild); `make deploy` (run from the Mac host, since it needs SSH) copies binaries and restarts units.
- `make vault-dev` (first planned as `dev-vault`; `dev-*` are the Mac-side container controls) runs a vault locally against `dev/` (gitignored: key, db, sockets, a policy naming your own user) for trying the CLI and Python client. Unit and socket tests run on macOS too (tokio's peer credentials work there); `/proc` cmdline in the audit is Linux-only and best effort.
- aegis-runner does not deploy aegis. Self-deploys fail in confusing ways; keep that path manual.
- Pinned toolchain (`rust-toolchain.toml`), committed `Cargo.lock`, `cargo-deny` and `cargo-audit` in `make` (`make deny`, `make audit`; run them when `Cargo.lock` changes). Dependencies are exact versions, each at least two weeks old when chosen.
- Runtime footprint should be a few MB per daemon, well within the box's memory.

## Tests that guard the promises

- Wrong uid on `read.sock` is refused; allowed uid gets only its scopes.
- `admin.sock` has no route that returns a value (route table test).
- Ciphertext moved to another row fails to decrypt.
- A wrong master key refuses to start.
- Delete then rollback restores the value; rollback re-encrypts under the new version.
- `write_only` admin callers get 403 on everything but store and generate.
- Bad scope or key names are refused before touching the store.
- Runner rejects unknown actions and out-of-enum parameters.
- aegis-web rejects requests without a valid session.
- aegis-infra `apply` never deletes without `--delete`, never touches unowned resources, and never writes a secret anywhere but a vault (no stdout, logs or files).

## Phases

1. **Dev container** (epiphyte). See "Dev containers" steps. After this, no dev work on icarus.
2. **Vault MVP in dev.** In this repo:
   - [x] Workspace, pinned toolchain, Makefile.
   - [x] Rust-only dev container, `aegis-dev` (`docs/dev-container.md`).
   - [x] Crypto: key derivation, seal/open with bound associated data, fingerprints, canary.
   - [x] Store: schema, versions, tombstones, rollback, audit rows.
   - [x] Policy: TOML, user names to uids, admin roles.
   - [x] Daemon: `read.sock` and `admin.sock` with peer-uid checks, master key from systemd credentials or a file.
   - [x] `aegis-vault-admin` CLI (value from stdin, never echoed) and `aegis-vault keygen`.
   - [x] Python client with tests.
   - [x] Example policy, systemd unit, `make vault-dev`, `make build-release`, `cargo-deny`/`cargo-audit` targets.
   - [ ] zig in the dev container image, so `make build-release` runs (needs a checksum looked up from the Mac); try the unit on a real systemd box.
   - [x] Sidecar image for other projects' dev containers: `make vault-image`, `etc/docker/aegis-vault/`, `docs/vault.md` "In a dev container".
   - [ ] epiphyte side (in epiphyte, not here): vendor the client, `secret_store.py` replaces the `secrets.py` symlink.
3. **Vault on prod.** Users, units, `systemd-creds` master key. Load existing secrets with the CLI. Switch prod off `secrets.py`, then delete it.
4. **aegis-infra, read-only.** `pull` and `plan` for Cloudflare and DigitalOcean, tokens via `op run`. Matches `etc/cloudflare/` output.
5. **aegis-infra apply.** Reissue the origin certificates into the vault and remove the tracked keys from git; rotate DB passwords and API tokens through the APIs into the vault (the old values have been read into AI sessions). Retire `etc/cloudflare/`.
6. **aegis-web.** SSH-tunnel access, passkey login, secrets pages, audit page.
7. **aegis-runner.** Wraps Make targets, narrow sudoers, jobs page. Deploys get short-lived Cloudflare tokens from infra. Retire `.env.local`.
8. **New boxes from nothing.** Droplet + cloud-init + vault + secrets + deploy, so a new app or a rebuilt icarus is one `apply`. Uniform deploys across sites, planned as its own step when the next app is added.
9. **Second project.** Another app adopts the vault: its own scopes in policy, the vendored Python client, the vault sidecar in its dev container.

## Open questions

- Backups of `vault.db` and the aegis-web DB: where, and how often?
- Should the CLI remain after the UI exists (break-glass access when aegis-web is down)? Leaning yes, root-only.
- Audit retention: rows are kept forever, and a process in `aegis-clients` can add them as fast as it can connect. Cap by count or age, or archive with the backups?
- Master key rotation: rows carry `kek_id`, but there's no re-encrypt command yet. Needed before the first rotation, not before Phase 3.
