#!/bin/bash
# Dev container controls. Run on the Mac host from the repo root, not inside the container.
# See docs/dev-container.md.
#
#   .devcontainer/dev.sh build       build the app image only
#   .devcontainer/dev.sh up          build and start, seed the repo if empty, run setup (safe to re-run)
#   .devcontainer/dev.sh push        push a branch (default: current) into the container's repo
#   .devcontainer/dev.sh shell       shell in the app container
#   .devcontainer/dev.sh down        stop (volumes and data are kept)
#   .devcontainer/dev.sh restart     rerun the start (firewall, Claude policy from dotfiles); no rebuild
#   .devcontainer/dev.sh ssh-config  add "Host aegis-dev" to ~/.ssh/config, for herdr (run once)
set -euo pipefail

if [ -f /.dockerenv ]; then
    echo "dev.sh runs on the Mac host, not inside the container." >&2
    exit 1
fi

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose -f "$script_directory/compose.yaml")
container_repo=/home/mdagosta/src/aegis

# Git is the only bridge between this checkout and the container's repo. Pushing runs git-receive-pack
# inside the container; fetching runs git-upload-pack inside. Neither runs anything from the container on
# this Mac: hooks and git config never travel.
push_to_container() {
    local branch="${1:-$(git -C "$script_directory/.." symbolic-ref --short HEAD)}"
    if ! grep -q "^Host aegis-dev\$" ~/.ssh/config 2>/dev/null; then
        echo "No 'Host aegis-dev' in ~/.ssh/config yet: run make dev-ssh-config first." >&2
        exit 1
    fi
    if ! git -C "$script_directory/.." remote get-url aegis-dev > /dev/null 2>&1; then
        git -C "$script_directory/.." remote add aegis-dev aegis-dev:src/aegis
        echo "added git remote: aegis-dev"
    fi
    # Check every object fetched from the container, so a malformed one can't reach a git bug here.
    git -C "$script_directory/.." config fetch.fsckObjects true
    # First push into an empty volume: an empty repo on the branch being pushed, so the push checks it out.
    if ! "${compose[@]}" exec -T --user mdagosta app test -d "$container_repo/.git"; then
        "${compose[@]}" exec -T --user mdagosta app git init --quiet --initial-branch="$branch" "$container_repo"
        echo "created an empty repo in the container on $branch"
    fi
    # Pushing the checked-out branch updates the working tree, and is refused if it has uncommitted changes.
    "${compose[@]}" exec -T --user mdagosta app git -C "$container_repo" config receive.denyCurrentBranch updateInstead
    git -C "$script_directory/.." push aegis-dev "$branch"
}

case "${1:-}" in
    build)
        "${compose[@]}" build app
        ;;
    up)
        "${compose[@]}" up -d --build
        # Seed only an empty repo volume. After that, updates are an explicit `dev.sh push`.
        if ! "${compose[@]}" exec -T --user mdagosta app test -d "$container_repo/.git"; then
            push_to_container
        fi
        # The Mac's copy of post-create.sh, piped in, so setup doesn't depend on what's committed inside.
        "${compose[@]}" exec -T --user mdagosta app bash -s < "$script_directory/post-create.sh"
        ;;
    push)
        push_to_container "${2:-}"
        ;;
    shell)
        "${compose[@]}" exec --user mdagosta app bash
        ;;
    down)
        "${compose[@]}" down
        ;;
    restart)
        # The entrypoint runs again: firewall re-resolved, Claude policy recopied from dotfiles. Ends every
        # shell and agent in the container.
        "${compose[@]}" restart app
        "${compose[@]}" logs app | grep -E 'firewall|entrypoint' | tail -2
        ;;
    ssh-config)
        # `ssh aegis-dev` (and herdr) reach the container through docker exec: sshd runs once per
        # connection and never listens, so there's no port. Host keys are skipped because they change
        # on every rebuild and the connection never touches the network. Full docker path, since GUI
        # apps like herdr don't get the shell's PATH.
        if grep -q "^Host aegis-dev\$" ~/.ssh/config 2>/dev/null; then
            echo "already in ~/.ssh/config: Host aegis-dev"
            exit 0
        fi
        docker_path="$(command -v docker)"
        printf '\n# Aegis dev container (.devcontainer/dev.sh ssh-config)\nHost aegis-dev\n    User mdagosta\n    ProxyCommand %s exec -i aegis-app-1 /usr/sbin/sshd -i\n    IdentityFile ~/.ssh/id_orpheus\n    IdentitiesOnly yes\n    ForwardAgent no\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n    LogLevel ERROR\n' "$docker_path" >> ~/.ssh/config
        echo "added to ~/.ssh/config: Host aegis-dev (try: ssh aegis-dev)"
        ;;
    *)
        sed -n '2,11p' "$0"
        exit 1
        ;;
esac
