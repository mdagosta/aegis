# aegis-vault

The secrets daemon: how it works, its API, and how to run it. The why is in `plan.md` ("aegis-vault").

## Pieces

| Piece | Where | What |
|---|---|---|
| `aegis-vault` | `crates/aegis-vault/src/main.rs` | `serve` (the daemon), `keygen`, `check-policy` |
| `aegis-vault-admin` | `crates/aegis-vault/src/bin/` | CLI for `admin.sock`: set, generate, delete, rollback, list, audit |
| Python client | `clients/python/aegis_vault.py` | `fetch_scope(scope)` over `read.sock`, stdlib only |
| Policy | `etc/aegis/policy.toml` | example; installed at `/etc/aegis/policy.toml` |
| Unit, users | `etc/systemd/aegis-vault.service`, `etc/sysusers.d/aegis-vault.conf` | hardened unit, `Type=notify` |
| Sidecar image | `etc/docker/aegis-vault/` | `make vault-image` on the Mac: the vault beside another project's dev container |

Library modules, in the order a request meets them: `server` (sockets, peer uid, handlers), `routes` (the
route tables as enums), `names` (scope, key and value rules), `policy`, `store` (SQLite, versions, audit),
`crypto` (keys, sealing, fingerprints). Plus `accounts` (`/etc/passwd`, `/etc/group`), `masterkey`,
`encoding`, `client` (the CLI's HTTP client).

## How a request is decided

1. The kernel reports the connecting process's uid and pid (`SO_PEERCRED`) when the connection is accepted.
2. A caller the policy doesn't know on that socket (on `read.sock`, no scope names it; on `admin.sock`,
   not in `[admin]`) gets 403 for any request at all, malformed ones included.
3. The path is parsed into a route, and the scope and key names are checked (400 if bad).
4. The role check: the scope's `allow_users` for a fetch; `full` or `write_only` for admin routes.
5. The store does the work and writes the audit row in the same transaction.

Every request gets an audit row (denied and malformed ones too) and a matching `audit ...` line on stderr,
which systemd puts in the journal. Neither ever holds a value. Each row records the caller's
`/proc/<pid>/cmdline`, so anything a caller puts on its own command line (already readable by everyone
on the box) ends up in the audit log too.

## Connections

Each uid may hold at most 16 connections to a socket at once (more are closed as soon as they're
accepted, unaudited); each socket at most 256 in all (more wait in the kernel's backlog); and a connection
that makes no progress for 30 seconds is closed. So one app, or one misbehaving uid, can't use up the
vault's file descriptors or another app's share. Request bodies over 512 KiB get 413, after the caller
check, with an audit row.

## Names and values

- Scope: segments of `[a-z0-9._-]` joined by `/`, e.g. `epiphyte/prod`. Key: `[A-Za-z0-9._-]`, e.g.
  `DATABASE_URL`. Each at most 128 bytes. No segment may be `.` or `..` (HTTP clients collapse those).
- Value: UTF-8 text, 1 byte to 64 KiB. Binary goes in base64.

## API

JSON over HTTP/1.1 on Unix sockets. Errors are `{"error": "message"}` with 400, 403, 404, 405, 413 or
500. A 500 says only "see the vault's journal"; the details are in the journal line.

### read.sock

`GET /v1/scope/{scope}`: for a uid in that scope's `allow_users`.

```json
{"scope": "epiphyte/prod", "secrets": {"DATABASE_URL": "...", "SMTP_PASSWORD": "..."}}
```

A scope that's allowed but has no live keys returns `"secrets": {}`. If any value fails to decrypt, the
whole request fails (500) rather than return part of the scope.

### admin.sock

No route returns a value. `write_only` callers may only `PUT` and `generate`, and only onto keys with no
versions yet or whose current version they wrote; everything else is 403.

| Request | Body | Answer |
|---|---|---|
| `GET /v1/scopes` | | every scope (the policy's and the store's) with `allow_users`, `in_policy` and its keys: `version`, `action`, `deleted`, `fingerprint`, `set_at`, `set_by` |
| `GET /v1/scope/{scope}/key/{key}/versions` | | `versions`, newest first: `version`, `action`, `deleted`, `fingerprint`, `rollback_of`, `set_at`, `set_by` |
| `PUT /v1/scope/{scope}/key/{key}` | `{"value": "..."}` | the write: `scope`, `key`, `version`, `action`, `fingerprint`, `rollback_of` |
| `DELETE /v1/scope/{scope}/key/{key}` | | the write (a tombstone version, `fingerprint` null). 404 if already deleted |
| `POST /v1/scope/{scope}/key/{key}/rollback` | `{"version": n}` | the write. 400 if version n is a delete |
| `POST /v1/scope/{scope}/key/{key}/generate` | `{"bytes": n}` or empty | the write. n random bytes (16 to 1024, default 32) as unpadded base64url |
| `GET /v1/audit?limit=n` | | `audit`, newest first (n from 1 to 1000, default 100) |

Scopes contain `/`, so the scope is everything between `/v1/scope/` and the `/key/{key}` near the end.
Keys can't contain `/`, which makes that split unambiguous.

## Storage and keys

- `vault.db` (SQLite, mode 0600) holds `secret` (every version of every key), `audit`, and `meta` (the
  master key's id and the canary).
- The current version of a key is its highest version. Set, generate, delete and rollback each add one, so
  any change can be undone and nothing is ever overwritten.
- Each value is sealed with XChaCha20-Poly1305 under a fresh random nonce, with the scope, key and version
  as associated data (each length-prefixed). A value copied to another row or version doesn't decrypt.
  Rollback decrypts the old version and seals it again for its new version.
- From the master key, HKDF-SHA256 derives the encryption key, a separate fingerprint key, and the key id
  (`kek_id`, 16 hex characters) stored with every row.
- A fingerprint is the first 6 bytes of HMAC-SHA256(fingerprint key, value), as 12 hex characters. Equal
  values have equal fingerprints, in any key or scope. Without the master key a fingerprint reveals
  nothing.
- At first start the vault seals a canary. A master key that doesn't match the store (wrong id, or a
  canary that won't open) stops the daemon before it serves anything or writes a row.
- Values are wiped from the vault's memory when dropped (`Zeroizing`), as far as the vault's own buffers
  go: hyper's and serde's internal buffers, and the Python client's strings, are out of reach.

## Running it

### Dev (in the container)

```
make vault-dev                               # dev/: key, store, sockets, a policy naming you
make vault-admin ARGS="set dev/example GREETING"   # type the value; it isn't echoed
echo value | make vault-admin ARGS="set dev/example OTHER"
make vault-admin ARGS="scopes"
make vault-fetch                               # the Python client; prints key names only
```

### In a dev container (a sidecar)

For another project's dev container (epiphyte-dev, snowballin-dev, ...): the vault runs in its own
container beside `app`, with no network, and `app` reaches its sockets through a shared volume.

1. Build the image on the Mac, in this repo: `make vault-image` (`etc/docker/aegis-vault/`). It's
   `aegis-vault:dev` on the Mac's docker; rebuild it to pick up vault changes.
2. Copy `etc/docker/aegis-vault/policy.dev.toml` into the project, under `~/src` (Colima shares only the
   home folder with containers), and name the project's scope.
3. Add to the project's compose file:

```yaml
services:
  vault:
    image: aegis-vault:dev
    pull_policy: never
    restart: unless-stopped
    network_mode: none
    # Root at start only, to install the policy and hand the volumes to aegis-vault; then it drops.
    cap_drop: [ALL]
    cap_add: [CHOWN, FOWNER, SETUID, SETGID]
    security_opt: [no-new-privileges:true]
    volumes:
      - ./vault-policy.toml:/config/policy.toml:ro
      - vault_run:/run/aegis-vault         # the sockets
      - vault_state:/var/lib/aegis-vault   # store and master key: never mounted in app
  app:
    depends_on: [vault]
    group_add: ["991", "992"]   # aegis-clients (read.sock), aegis-admin (admin.sock): numbers, not names
    volumes:
      - vault_run:/run/aegis-vault:ro   # read-only: app can connect, but can't put its own socket there
volumes:
  vault_run:
  vault_state:
```

4. In app's Dockerfile, the admin CLI: `COPY --from=aegis-vault:dev /usr/local/bin/aegis-vault-admin
   /usr/local/bin/` (a static binary). Copy `clients/python/aegis_vault.py` into the project. Both
   default to the sockets in `/run/aegis-vault`, so nothing needs configuring.
5. Fill the scope from app: `aegis-vault-admin generate myproject/dev COOKIE_SECRET`, or
   `... set myproject/dev KEY` with the value on stdin. Fetch with `fetch_scope("myproject/dev")`.

How it fits:

- The caller is known by uid alone; its pid is in another container, so the audit rows show `pid 0` and
  no command line. Policy names resolve in the image's `/etc/passwd`, which has `mdagosta` at 1000
  (`CLIENT_USER` and `CLIENT_UID` build arguments, if a project ever needs another).
- The master key is made on first start and kept with the store in `vault_state`. Dev only: delete that
  volume and the dev secrets go with it.
- **What this doesn't separate:** whoever runs as the reader's uid in app can fetch the scope. If the app
  server and Claude both run as `mdagosta`, Claude can read the dev secrets through the socket; the vault
  keeps them out of files, not out of reach. Running the server under its own uid (and naming only that
  uid in the scope) is what separates them, as on prod.

### Prod (Phase 3)

1. Users and groups: install `etc/sysusers.d/aegis-vault.conf`, run `systemd-sysusers`. Add each app's
   user to `aegis-clients`, and aegis-web's user (and later `aegis-infra`) to `aegis-admin`.
2. Policy: install `etc/aegis/policy.toml` as `/etc/aegis/policy.toml` (root, 0644), edited for the box.
   `aegis-vault check-policy` shows what it resolves to.
3. Master key, as root:
   ```
   aegis-vault keygen --out /root/aegis-master-key
   systemd-creds encrypt --name=aegis-master-key /root/aegis-master-key \
       /etc/credstore.encrypted/aegis-master-key
   ```
   Copy the key into 1Password, then `shred -u /root/aegis-master-key`.
4. Unit: install `etc/systemd/aegis-vault.service`, then `systemctl enable --now aegis-vault`.
5. Load secrets: `sudo aegis-vault-admin set epiphyte/prod DATABASE_URL`, typed or piped (`op read ... |`).
   A piped value loses one trailing newline.

The vault refuses to start if its run directory, its store's directory, or its policy (file or directory)
is writable by group or others: whoever can write there could swap in their own sockets, store or policy.

`aegis-vault serve` defaults: `--policy /etc/aegis/policy.toml`, `--db /var/lib/aegis-vault/vault.db`,
`--run-dir /run/aegis-vault`, master key from `$CREDENTIALS_DIRECTORY/aegis-master-key`
(`--master-key <file>` instead, for dev; it must be 0600 or tighter).

## Not yet

- Master key rotation: the schema keeps `kek_id` per row for it, but there's no command yet.
- `aegis-vault-admin --stdio` (the forced command for aegis-infra's SSH key): with aegis-infra, Phase 4/5.
- Audit retention: rows are kept forever. A caller in `aegis-clients` that hammers `read.sock` grows the
  table; decide on a cap when backups are decided.
- Rate limits: none. A process allowed to connect can send requests as fast as it likes; each is
  refused (or served) and audited.
