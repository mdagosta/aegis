# aegis-vault as a sidecar for dev containers (docs/vault.md, "In a dev container"). Build it on the Mac
# with `make vault-image`; projects use the image by name, aegis-vault:dev.
#
# The build context is the repo root, cut down by Dockerfile.dockerignore beside this file to the
# workspace and this folder: dev/ (a dev vault's key and store) and target/ never enter it.

# Static musl binaries, so a dev container can also copy aegis-vault-admin out of this image
# (COPY --from=aegis-vault:dev). Base images pinned by digest.
FROM rust:1.96.0-alpine3.22@sha256:8c6ab6493f2e93ee7c21781bc599a7e07278aceb15fefb968144d7e4cf8c9a04 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
# No rust-toolchain.toml: it names components and an x86_64 target for icarus builds, which rustup would
# download; this image's toolchain is the same version.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --locked --release --bin aegis-vault --bin aegis-vault-admin \
    && mkdir /out && cp target/release/aegis-vault target/release/aegis-vault-admin /out/

FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
# The dev containers' user, so a policy can name it: the vault turns names into uids from this image's
# /etc/passwd, and a caller in another container shows up by its uid alone.
ARG CLIENT_USER=mdagosta
ARG CLIENT_UID=1000
# Fixed ids, since other containers use them by number: aegis-clients (991) owns read.sock and
# aegis-admin (992) owns admin.sock, when the policy's [sockets] names them; a dev container joins one
# with compose's group_add.
RUN userdel --remove ubuntu 2>/dev/null || true; \
    groupadd --system --gid 990 aegis-vault \
    && useradd --system --uid 990 --gid 990 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin aegis-vault \
    && groupadd --system --gid 991 aegis-clients \
    && groupadd --system --gid 992 aegis-admin \
    && usermod --append --groups aegis-clients,aegis-admin aegis-vault \
    && useradd --uid ${CLIENT_UID} --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin ${CLIENT_USER}
COPY --from=build /out/ /usr/local/bin/
COPY etc/docker/aegis-vault/entrypoint.sh /usr/local/bin/aegis-vault-entrypoint
RUN chmod 755 /usr/local/bin/aegis-vault-entrypoint
ENTRYPOINT ["/usr/local/bin/aegis-vault-entrypoint"]
