#!/bin/bash
# Runs as root at container start. Puts up the outbound firewall, installs the Claude Code policy, hands
# new named volumes to the dev user, then drops privileges and idles.
set -euo pipefail
# Root-owned directories only: the image's PATH starts with the dev user's own bin directories, and
# anything the dev user put there would otherwise run here as root, before the firewall.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# First, and fatal on failure (set -e): the container never runs without it.
/usr/local/bin/aegis-firewall

# Keep up with allowlisted hosts' rotating addresses, as root, for the life of the container.
(while sleep 1800; do /usr/local/bin/aegis-firewall refresh || true; done) &

# Claude Code's shared policy comes from the Mac's dotfiles, the same files the Mac installs for every
# account. Copied as root into root-owned files, so nothing here can change it. Fatal if missing.
policy_source=/run/host-dotfiles/claude/managed-settings.d
if ! ls "$policy_source"/*.json > /dev/null 2>&1; then
    echo "entrypoint: no Claude Code policy in $policy_source (the Mac's ~/src/dotfiles/claude/managed-settings.d)" >&2
    exit 1
fi
rm -rf /etc/claude-code/managed-settings.d
install -d -o root -g root -m 755 /etc/claude-code/managed-settings.d
install -o root -g root -m 644 "$policy_source"/*.json /etc/claude-code/managed-settings.d/

# Volume top directories only, not recursive: the repo's contents come from git as the dev user.
for volume_directory in \
    /home/mdagosta/src/aegis \
    /home/mdagosta/.claude \
    /home/mdagosta/.cargo/registry
do
    chown mdagosta:mdagosta "$volume_directory"
done

# The Mac's SSH public key (compose mounts it read-only), owned by root so sshd's StrictModes accepts it.
if [ -f /run/host-ssh/authorized_key.pub ]; then
    install -o root -g root -m 644 /run/host-ssh/authorized_key.pub /etc/ssh/authorized_keys/mdagosta
fi

echo "entrypoint: ready"
exec setpriv --reuid=mdagosta --regid=mdagosta --init-groups sleep infinity
