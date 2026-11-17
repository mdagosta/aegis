#!/bin/sh
# Starts as root only to set up what the vault insists on, then runs it as aegis-vault:
# - the policy, mounted from the Mac (owned by the Mac's user), copied to a root-owned file;
# - the run and store directories (named volumes, root-owned when new) handed to aegis-vault, 0755 and 0700;
# - a master key on first start, kept with the store. Dev only: on a server it comes from systemd-creds.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

policy_source=/config/policy.toml
run_dir=/run/aegis-vault
state_dir=/var/lib/aegis-vault

if [ ! -f "$policy_source" ]; then
    echo "aegis-vault-entrypoint: no policy at $policy_source (mount the project's policy file there)" >&2
    exit 1
fi
install -d -o root -g root -m 755 /etc/aegis
install -o root -g root -m 644 "$policy_source" /etc/aegis/policy.toml
install -d -o aegis-vault -g aegis-vault -m 755 "$run_dir"
install -d -o aegis-vault -g aegis-vault -m 700 "$state_dir"

as_vault() {
    setpriv --reuid=aegis-vault --regid=aegis-vault --init-groups "$@"
}
# As aegis-vault: root here has no CAP_DAC_OVERRIDE, so it can't look inside the 0700 store directory.
if ! as_vault test -f "$state_dir/master.key"; then
    as_vault /usr/local/bin/aegis-vault keygen --out "$state_dir/master.key"
    echo "aegis-vault-entrypoint: made a new master key in $state_dir"
fi
exec setpriv --reuid=aegis-vault --regid=aegis-vault --init-groups \
    /usr/local/bin/aegis-vault serve --policy /etc/aegis/policy.toml --db "$state_dir/vault.db" --run-dir "$run_dir" \
        --master-key "$state_dir/master.key"
