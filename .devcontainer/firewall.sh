#!/bin/bash
# Outbound firewall for the dev container, after epiphyte's (and Claude Code's reference devcontainer).
# Runs as root from the entrypoint at every start, before privileges drop.
#
# In:  loopback and replies. Nothing is published, so nothing else comes in.
# Out: loopback (Docker's DNS), then by AEGIS_FIREWALL_MODE (set in compose.yaml, default allowlist here):
#      allowlist  HTTPS only to the hosts in /etc/aegis-dev/firewall-allowlist plus GitHub.
#      open-https HTTPS to any public address. Private, link-local, shared and multicast ranges are
#                 refused first, so the container still can't reach the Mac, the LAN or the Docker host.
#                 This gives up the exfiltration fence: anything readable in the container can be sent
#                 to any host. Go back to allowlist if that matters more than reaching the web.
#      Everything else is refused in both.
#
# Any failure exits non-zero, so the container doesn't start rather than starting unprotected.
#
# `aegis-firewall refresh` (the entrypoint runs it every half hour) only adds the current addresses of
# the allowlisted hosts, since CDN-backed hosts rotate theirs. Old addresses stay allowed until the next
# start. In open-https mode there is nothing to refresh.
set -euo pipefail
# Root-owned directories only: the image's PATH starts with the dev user's own bin directories.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

allowlist_file=/etc/aegis-dev/firewall-allowlist
fail() { echo "firewall: $*" >&2; exit 1; }
warn() { echo "firewall: $*" >&2; }

mode="${AEGIS_FIREWALL_MODE:-allowlist}"
case "$mode" in
    allowlist | open-https) ;;
    *) fail "AEGIS_FIREWALL_MODE must be allowlist or open-https, not '$mode'" ;;
esac

# Never reachable in open-https mode: "this network" (OrbStack's host.docker.internal is 0.250.250.254),
# private (RFC 1918: the Mac, the LAN, Docker's gateway, Docker Desktop's VM at 192.168.65.0/24),
# shared/CGNAT, link-local (cloud metadata), IETF protocol, benchmarking, and multicast plus reserved
# space. Only IPv4 matters: the container has no IPv6.
blocked_ranges="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3"

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
    [ "$mode" = allowlist ] && add_current_addresses warn
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

if [ "$mode" = allowlist ]; then
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
fi

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
if [ "$mode" = allowlist ]; then
    iptables -A OUTPUT -p tcp --dport 443 -m set --match-set allowed-hosts dst -j ACCEPT
else
    for range in $blocked_ranges; do
        iptables -A OUTPUT -d "$range" -j REJECT --reject-with icmp-admin-prohibited
    done
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
fi
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

# Prove it.
if [ "$mode" = allowlist ]; then
    # An unlisted host is refused, a listed one works.
    if curl --silent --max-time 5 https://example.com > /dev/null 2>&1; then
        fail "example.com is reachable; the rules didn't take"
    fi
    curl --silent --max-time 10 https://api.github.com/zen > /dev/null || fail "api.github.com is unreachable"
    echo "firewall: up, allowlist ($(ipset list allowed-hosts | grep -cE '^[0-9]') allowed addresses)"
else
    # The public internet works, and every private range is refused by a rule that's actually there.
    curl --silent --max-time 10 https://api.github.com/zen > /dev/null || fail "api.github.com is unreachable"
    for range in $blocked_ranges; do
        iptables -C OUTPUT -d "$range" -j REJECT --reject-with icmp-admin-prohibited \
            || fail "no rule refusing $range"
    done
    if curl --silent --max-time 5 https://192.168.0.1 > /dev/null 2>&1 || \
        curl --silent --max-time 5 https://10.0.0.1 > /dev/null 2>&1; then
        fail "a private address is reachable; the rules didn't take"
    fi
    echo "firewall: up, open-https (private ranges refused)"
fi
