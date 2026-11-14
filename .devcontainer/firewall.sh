#!/bin/bash
# Outbound firewall for the dev container, after epiphyte's (and Claude Code's reference devcontainer).
# Runs as root from the entrypoint at every start, before privileges drop.
#
# In:  loopback and replies. Nothing is published, so nothing else comes in.
# Out: loopback (Docker's DNS) and HTTPS to the hosts in /etc/aegis-dev/firewall-allowlist plus GitHub.
#      Everything else is refused.
#
# Any failure exits non-zero, so the container doesn't start rather than starting unprotected.
#
# `aegis-firewall refresh` (the entrypoint runs it every half hour) only adds the current addresses of
# the allowlisted hosts, since CDN-backed hosts rotate theirs. Old addresses stay allowed until the next
# start.
set -euo pipefail
# Root-owned directories only: the image's PATH starts with the dev user's own bin directories.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

allowlist_file=/etc/aegis-dev/firewall-allowlist
fail() { echo "firewall: $*" >&2; exit 1; }
warn() { echo "firewall: $*" >&2; }

# Adds every current address of the allowlisted hosts to allowed-hosts. $1 is what to do with a name
# that doesn't resolve: fail at start, warn on a refresh.
add_current_addresses() {
    local on_unresolved="$1" line host addresses address
    while IFS= read -r line; do
        host="${line%%#*}"
        host="$(echo "$host" | tr -d '[:space:]')"
        [ -n "$host" ] || continue
        addresses="$(dig +short A "$host" | grep -E '^[0-9]+(\.[0-9]+){3}$' || true)"
        if [ -z "$addresses" ]; then
            "$on_unresolved" "couldn't resolve $host"
            continue
        fi
        while IFS= read -r address; do
            ipset add allowed-hosts "$address" -exist
        done <<< "$addresses"
    done < "$allowlist_file"
}

if [ "${1:-}" = refresh ]; then
    add_current_addresses warn
    exit 0
fi

# Docker's DNS at 127.0.0.11 works through NAT rules Docker put in this namespace. Keep them across the flush.
docker_dns_rules="$(iptables-save -t nat | grep '127\.0\.0\.11' || true)"

iptables -F; iptables -X
iptables -t nat -F; iptables -t nat -X
iptables -t mangle -F; iptables -t mangle -X
ipset destroy allowed-hosts 2>/dev/null || true

if [ -n "$docker_dns_rules" ]; then
    iptables -t nat -N DOCKER_OUTPUT 2>/dev/null || true
    iptables -t nat -N DOCKER_POSTROUTING 2>/dev/null || true
    while IFS= read -r rule; do
        # Each saved line is "-A CHAIN ...": its words are the iptables arguments.
        read -r -a rule_arguments <<< "$rule"
        iptables -t nat "${rule_arguments[@]}"
    done <<< "$docker_dns_rules"
else
    fail "no Docker DNS rules found; is this a compose network?"
fi

# Resolve everything while the network is still open.
ipset create allowed-hosts hash:net

github_meta="$(curl --silent --show-error --fail --max-time 15 https://api.github.com/meta)" \
    || fail "couldn't fetch GitHub's address ranges from api.github.com/meta"
github_ranges="$(echo "$github_meta" | jq -r '(.web + .api + .git)[]' | grep -E '^[0-9.]+/[0-9]+$' | aggregate -q)"
[ -n "$github_ranges" ] || fail "no GitHub ranges in api.github.com/meta"
while IFS= read -r github_range; do
    ipset add allowed-hosts "$github_range" -exist
done <<< "$github_ranges"

add_current_addresses fail

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m set --match-set allowed-hosts dst -j ACCEPT
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
# Refuse rather than drop, so a blocked request fails at once instead of hanging until a timeout.
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

# No IPv6 at all. The compose network has none today; this keeps it that way if that changes.
if ip6tables -L > /dev/null 2>&1; then
    ip6tables -F
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
fi

# Prove it: an unlisted host is refused, a listed one works.
if curl --silent --max-time 5 https://example.com > /dev/null 2>&1; then
    fail "example.com is reachable; the rules didn't take"
fi
curl --silent --max-time 10 https://api.github.com/zen > /dev/null || fail "api.github.com is unreachable"
echo "firewall: up ($(ipset list allowed-hosts | grep -cE '^[0-9]') allowed addresses)"
