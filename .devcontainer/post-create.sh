#!/bin/bash
# Setup inside the dev container, as the dev user. Safe to re-run; `dev.sh up` runs it each time, piping
# in the Mac's copy (so it works before this file is committed and pushed in).
set -euo pipefail
cd /home/mdagosta/src/aegis

# The Mac's ~/src/dotfiles, mounted read-only so nothing in here can change what the Mac's shell runs.
# Each top-level dotfile is linked into $HOME; directories are not, since programs write into them.
echo "=== Dotfiles ==="
if [ -d /run/host-dotfiles ]; then
    for dotfile in /run/host-dotfiles/.[!.]*; do
        [ -f "$dotfile" ] || continue
        ln -sfn "$dotfile" "$HOME/$(basename "$dotfile")"
        echo "linked ~/$(basename "$dotfile")"
    done
    # Claude: shared instructions plus this machine's (CLAUDE.aegis-dev.md, if the dotfiles have one),
    # which CLAUDE.md imports as CLAUDE.machine.md. The login, history and transcripts stay here.
    claude_directory="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
    if [ -f /run/host-dotfiles/claude/CLAUDE.md ]; then
        ln -sfn /run/host-dotfiles/claude/CLAUDE.md "$claude_directory/CLAUDE.md"
        echo "linked $claude_directory/CLAUDE.md"
    fi
    machine_file="/run/host-dotfiles/claude/CLAUDE.$(hostname).md"
    if [ -f "$machine_file" ]; then
        ln -sfn "$machine_file" "$claude_directory/CLAUDE.machine.md"
        echo "linked $claude_directory/CLAUDE.machine.md"
    else
        echo "no $machine_file in the dotfiles (optional)"
    fi
    if [ -d /run/host-dotfiles/claude/skills ]; then
        mkdir -p "$claude_directory/skills"
        for skill in /run/host-dotfiles/claude/skills/*/; do
            [ -d "$skill" ] || continue
            ln -sfn "${skill%/}" "$claude_directory/skills/$(basename "$skill")"
            echo "linked skill $(basename "$skill")"
        done
    fi
    # Statusline: link the Mac's script and point settings.json at it; settings.json stays the
    # container's own file, so only this one key is set.
    if [ -f /run/host-dotfiles/claude/statusline.sh ]; then
        ln -sfn /run/host-dotfiles/claude/statusline.sh "$claude_directory/statusline.sh"
        settings_file="$claude_directory/settings.json"
        [ -s "$settings_file" ] || echo '{}' > "$settings_file"
        jq --arg command "bash $claude_directory/statusline.sh" \
            '.statusLine = {type: "command", command: $command}' \
            "$settings_file" > "$settings_file.new" && mv "$settings_file.new" "$settings_file"
        echo "linked $claude_directory/statusline.sh"
    fi
fi

echo "=== Rust ==="
# rust-toolchain.toml names the same version the image installed, so this downloads nothing.
cargo fetch --locked
cargo --version

echo "=== Ready: make dev-shell (or ssh aegis-dev), then make check ==="
