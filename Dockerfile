# syntax=docker/dockerfile:1
#
# totem container image (PLAN.md section 13).
# Build: docker build -t totem:latest .
#
# Uses the host's pcscd through the mounted /run/pcscd socket. The pcsc-lite
# client here (pcsc-lite 2.x, protocol 4:5) must speak the same protocol as
# the host's pcscd. Hosts with pcsc-lite 1.x (protocol 4:4, e.g. Debian
# bookworm) need the runtime base image matched to the host distro.

FROM rust:1-trixie AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcsclite-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY static static
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/totem /totem

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcsclite1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /totem /usr/local/bin/totem
# Numeric non-root user: nothing in the image needs a passwd entry, and the
# root filesystem can be mounted read-only.
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/totem"]
