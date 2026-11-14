# Checking the vault's unit on a real systemd box

Nothing in the dev container runs systemd, so the unit (`etc/systemd/aegis-vault.service`), the sysusers
file and the credential path have only been read, not run. This is the list to run through on the first
box that has them: icarus, or a throwaway VM first. The steps for installing are in `vault.md` ("Prod").

Run as root. Sections A to E are safe before any real secret is loaded; **do D before loading them**,
since it stops the vault and swaps its key. On icarus, nothing depends on the vault until Phase 3 switches
epiphyte over, so that's the window.

## A. Before starting

| Check | Command | Expect |
|---|---|---|
| Right binaries | `uname -m; aegis-vault --version` | `x86_64`, a version (the arm64 dev container can't run these) |
| systemd knows credentials | `systemctl --version \| head -1` | 250 or newer (`LoadCredentialEncrypted=`); Ubuntu 24.04 has 255 |
| Users made | `systemd-sysusers; getent passwd aegis-vault; getent group aegis-clients aegis-admin` | all three exist; `aegis-vault`'s shell is `/usr/sbin/nologin` |
| Policy resolves | `aegis-vault check-policy` | every user and group resolves to an id; no error |
| Policy not writable | `ls -l /etc/aegis/policy.toml` | `-rw-r--r-- root root` |
| Credential made | `systemd-creds encrypt` as in the unit header, then `ls -l /etc/credstore.encrypted/` | the file exists; if `encrypt` complains about a host key, see `systemd-creds setup` |
| Credential opens | `systemd-creds decrypt /etc/credstore.encrypted/aegis-master-key \| wc -c` | a plausible key length, and no key text on screen |

`systemd-creds has-tpm2` says whether the credential is bound to a TPM. Without one it's encrypted with a
host key on the same disk: it still keeps the key out of the vault's own user and out of backups of
`/etc`, but not from root or someone with the disk.

## B. Start, and the sandbox

`systemctl enable --now aegis-vault`, then:

| Check | Command | Expect |
|---|---|---|
| Reached ready | `systemctl status aegis-vault` | `active (running)`, not stuck in `activating` (`Type=notify`: READY=1 comes once both sockets exist) |
| Quiet journal | `journalctl -u aegis-vault -b --no-pager` | a start line; no errors; no secret, no key |
| Run dir | `ls -ld /run/aegis-vault; ls -l /run/aegis-vault` | dir `drwxr-xr-x aegis-vault`; `read.sock` `srw-rw---- aegis-vault aegis-clients`; `admin.sock` `srw-rw---- aegis-vault aegis-admin` |
| State dir | `ls -ld /var/lib/aegis-vault; ls -l /var/lib/aegis-vault` | dir `drwx------ aegis-vault`; `vault.db` `-rw-------` |
| No capabilities, no new privileges | `grep -E 'CapEff\|NoNewPrivs\|Seccomp:' /proc/$(systemctl show -p MainPID --value aegis-vault)/status` | `CapEff` all 0, `NoNewPrivs: 1`, `Seccomp: 2` |
| Limits | `grep -E 'open files\|core file' /proc/$(systemctl show -p MainPID --value aegis-vault)/limits` | 2048 open files; core file size 0 |
| No network | `nsenter -t $(systemctl show -p MainPID --value aegis-vault) -n ip -br addr` | only `lo` (`PrivateNetwork=yes`) |
| Credential is private | `ls -ld /run/credentials/aegis-vault.service` | not readable by others |
| Hardening score | `systemd-analyze security aegis-vault --no-pager` | read the list: the two gaps we chose on purpose are `PrivateUsers` and `ProtectProc` (see the unit's comments). Anything else flagged is worth a look |

## C. Doing the job

Add a scratch scope to `/etc/aegis/policy.toml` so a read can be tried, then `systemctl restart aegis-vault`
(the policy is read at start):

```
[scope."aegis/selfcheck"]
allow_users = ["root"]
```

| Check | Command | Expect |
|---|---|---|
| Set from stdin | `printf pong \| aegis-vault-admin set aegis/selfcheck PING` | a write: version 1, `action` set, a fingerprint, no value |
| Generate | `aegis-vault-admin generate aegis/selfcheck TOKEN` | a write with a fingerprint; the value isn't shown |
| Metadata only | `aegis-vault-admin scopes` | `aegis/selfcheck` with `PING` and `TOKEN`, `in_policy` true; no values anywhere |
| Read as an allowed uid | `python3 -I -c 'import sys; sys.path.insert(0, "DIR"); import aegis_vault as v; print(sorted(v.fetch_scope("aegis/selfcheck")))'` (`DIR` holds a copy of `clients/python/aegis_vault.py`) | `['PING', 'TOKEN']`, names only |
| Rollback and versions | `aegis-vault-admin delete aegis/selfcheck PING`, then `versions aegis/selfcheck PING`, then `rollback aegis/selfcheck PING 1` | a tombstone version 2, then version 3 restoring version 1's value |
| Audit rows | `aegis-vault-admin audit --limit 10` | one row per request above, with your user and the `aegis-vault-admin` command line (this is the `/proc/<pid>/cmdline` the unit leaves visible); no values |
| Audit in the journal | `journalctl -u aegis-vault -b --no-pager \| grep audit` | matching `audit ...` lines |

The fence, outer then inner. As a user that isn't in the groups:

| Check | Command | Expect |
|---|---|---|
| Outer: admin | `sudo -u nobody aegis-vault-admin scopes` | permission denied at connect; no audit row |
| Outer: read | `sudo -u nobody python3 -I -c '...fetch_scope("aegis/selfcheck")'` | same |
| Inner: in the group, not in the policy | `usermod -aG aegis-clients nobody`, then the same fetch as `nobody` | 403, and a denied audit row for `nobody`. Undo: `gpasswd -d nobody aegis-clients` |

## D. Refusals (before real secrets are loaded)

Each should stop the vault with a clear message, not serve. `journalctl -u aegis-vault -n 20` shows it, and
`Restart=on-failure` will keep retrying every 2 seconds, so `systemctl stop aegis-vault` after.

| Break | How | Expect |
|---|---|---|
| Wrong master key | keep a copy of `/etc/credstore.encrypted/aegis-master-key`, replace it with the encryption of a different `keygen` key, start | refused before serving (key id or canary mismatch), no audit row written. Put the original back |
| Group-writable policy | `chmod g+w /etc/aegis/policy.toml`, start | refuses the policy. `chmod g-w` after |
| Group-writable store dir | `chmod g+rx,g+w /var/lib/aegis-vault` | refuses the directory. Restore `0700` |
| Bad policy | add a user that doesn't exist | refuses, naming it; also what `aegis-vault check-policy` reports |

Then start it with everything restored, and re-run B's "Reached ready".

## E. Restart and reboot

| Check | Command | Expect |
|---|---|---|
| Survives a restart | `systemctl restart aegis-vault`, then `aegis-vault-admin scopes` | the same keys and versions |
| Survives a reboot | `reboot`, then `systemctl is-active aegis-vault` | `active`, with no hand-holding: the credential decrypts on its own |
| Comes back if killed | `kill -9 $(systemctl show -p MainPID --value aegis-vault)`, wait 3 seconds | running again (`Restart=on-failure`), new sockets, same data |

## F. Clean up

Remove the `aegis/selfcheck` entry from the policy and restart. Its versions and audit rows stay in the
store, since nothing is ever overwritten or removed: say so when loading the real secrets, so nobody
wonders about them. If a throwaway VM was used, delete it.

What this doesn't cover: apps that wait for the vault (`After=aegis-vault.service`), which belong to the
epiphyte step, and master key rotation, which doesn't exist yet.
