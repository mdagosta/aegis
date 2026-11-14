# Aegis dev container: Rust only. Ubuntu 24.04 to match icarus. Copied from epiphyte's .devcontainer
# (its docs/dev-containers.md and docs/adr/ hold the reasons); see docs/dev-container.md here.
# Build context is .devcontainer/ only, so the repo (and anything secret in it) never enters the image.
FROM ubuntu:24.04

# Keep in step with rust-toolchain.toml, so cargo never has to download a toolchain at run time.
ARG RUST_VERSION=1.96.0
ARG USERNAME=mdagosta
ARG USER_UID=1000
ARG USER_GID=1000

# PATH starts with directories the dev user can write, so the root scripts (entrypoint, firewall) set
# their own.
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    CLAUDE_CONFIG_DIR=/home/mdagosta/.claude \
    PATH=/home/mdagosta/.cargo/bin:/home/mdagosta/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# python3 is for the vault's Python client and its tests (stdlib only). sqlite3 is for looking at a dev
# vault.db (ciphertext only).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ack build-essential ca-certificates curl emacs-nox git jq less openssh-server pkg-config procps \
        python3 sqlite3 tig tmux unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu's image ships a user "ubuntu" at uid 1000; replace it with ours. No sudo: system changes go
# through this file and a rebuild.
RUN userdel --remove ubuntu 2>/dev/null || true; \
    groupadd --gid ${USER_GID} ${USERNAME}; \
    useradd --uid ${USER_UID} --gid ${USER_GID} --create-home --shell /bin/bash ${USERNAME}; \
    mkdir -p /home/${USERNAME}/src/aegis /home/${USERNAME}/.claude /home/${USERNAME}/.cargo/registry; \
    chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}

# SSH for herdr (see sshd/aegis.conf). Host keys are made at build, so they change on rebuild; the Mac's
# ssh config entry skips host key checks, since the connection is docker exec, never the network.
# /etc/environment gives SSH sessions the same variables as `docker exec` shells (sshd doesn't pass ENV).
COPY sshd/aegis.conf /etc/ssh/sshd_config.d/aegis.conf
RUN ssh-keygen -A; \
    mkdir -p /run/sshd /etc/ssh/authorized_keys; \
    printf 'LANG=%s\nCLAUDE_CONFIG_DIR=%s\nPATH=%s\n' "$LANG" "$CLAUDE_CONFIG_DIR" "$PATH" > /etc/environment

# Outbound firewall (firewall.sh, run by the entrypoint as root at every start): iptables and ipset for the
# rules, dig to resolve the allowlist, aggregate to merge GitHub's ranges.
RUN apt-get update && apt-get install -y --no-install-recommends aggregate dnsutils ipset iptables \
    && rm -rf /var/lib/apt/lists/*
COPY firewall.sh /usr/local/bin/aegis-firewall
COPY firewall-allowlist /etc/aegis-dev/firewall-allowlist
RUN chmod 755 /usr/local/bin/aegis-firewall

COPY entrypoint.sh /usr/local/bin/aegis-entrypoint
RUN chmod 755 /usr/local/bin/aegis-entrypoint

USER ${USERNAME}
# The musl target is for icarus release builds; rust-toolchain.toml lists it too.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION} --component clippy,rustfmt \
            --target x86_64-unknown-linux-musl
# Dependency checks (make deny, make audit) and release builds (make build-release). Exact versions, each
# at least two weeks old when chosen; --locked builds each from its own lockfile. The registry is cleared
# after, since it's a volume at run time.
RUN cargo install --locked cargo-deny@0.20.2 cargo-audit@0.22.2 cargo-zigbuild@0.24.0 \
    && rm -rf /home/${USERNAME}/.cargo/registry/cache /home/${USERNAME}/.cargo/registry/index \
        /home/${USERNAME}/.cargo/registry/src
# zig, which cargo-zigbuild needs as the C compiler and linker (SQLite is C). A pinned download from
# ziglang.org (the aarch64 build, since the image is native arm64) with its SHA-256 checked here: a
# release at least two weeks old, hash from https://ziglang.org/download/index.json. Under ~/.local, which
# is on PATH.
ARG ZIG_VERSION=0.17.0
ARG ZIG_SHA256=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8
RUN curl --proto '=https' --tlsv1.2 -fsSLO https://ziglang.org/download/${ZIG_VERSION}/zig-aarch64-linux-${ZIG_VERSION}.tar.xz \
    && echo "${ZIG_SHA256}  zig-aarch64-linux-${ZIG_VERSION}.tar.xz" | sha256sum -c - \
    && mkdir -p /home/${USERNAME}/.local/bin \
    && tar -xJf zig-aarch64-linux-${ZIG_VERSION}.tar.xz -C /home/${USERNAME}/.local \
    && ln -s /home/${USERNAME}/.local/zig-aarch64-linux-${ZIG_VERSION}/zig /home/${USERNAME}/.local/bin/zig \
    && rm zig-aarch64-linux-${ZIG_VERSION}.tar.xz \
    && zig version
RUN curl -fsSL https://claude.ai/install.sh | bash
# herdr's server, so herdr on the Mac can attach to agents running here. --version fails the build if
# the installer put it somewhere off PATH.
RUN curl -fsSL https://herdr.dev/install.sh | sh && herdr --version
# herdr-core (`hc`), which the herdr app on the Mac runs on the machine it's attached to. Its installer
# verifies the download's SHA-256 and only writes ~/.local.
RUN curl -fsSL https://releases.herdr.dev/core/install.sh | sh && hc --version

# Claude Code managed settings: root-owned (COPY ignores USER), so Claude, running as mdagosta, can't edit
# them. Only what's specific to the container (auto-updater off: updates come by rebuild); the shared
# policy comes from the Mac's dotfiles at every start (entrypoint.sh). Last, so changing it rebuilds only
# this layer.
COPY claude/managed-settings.json /etc/claude-code/managed-settings.json

# The entrypoint starts as root only to put up the firewall and fix named-volume ownership, then drops
# to the user.
USER root
WORKDIR /home/mdagosta/src/aegis
ENTRYPOINT ["/usr/local/bin/aegis-entrypoint"]
