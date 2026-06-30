# syntax=docker/dockerfile:1
# Single-binary sconce: one `serve` process runs the Composer wire API, the
# admin UI, and the in-process mirror worker. Postgres is the only dependency.
#
# Published multi-arch (linux/amd64 + linux/arm64) by
# .github/workflows/build-docker.yml on Depot's native per-arch builders — no
# QEMU, no cross-compile. This Dockerfile compiles natively on each arch.

# Tracks rust-toolchain.toml (the toolchain file still wins at build time; this
# only picks the base image). Bumps flow through PRs so the image stays pinned.
ARG RUST_VERSION=1.96

# ---- build ----
# rustls everywhere (sqlx, ureq) so the build needs no OpenSSL/native libs.
FROM rust:${RUST_VERSION}-slim-bookworm AS build
WORKDIR /src
# Materialize the toolchain pinned by rust-toolchain.toml before the sources so
# this layer stays cached across source-only changes.
COPY rust-toolchain.toml .
RUN rustup toolchain install
COPY . .
# Cargo registry/git + the target dir are BuildKit cache mounts: they live on
# the builder and never bloat the image, so reruns are fast. Copy the binary
# out of the target cache in the same RUN so it survives into the next layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --bin sconce \
 && cp target/release/sconce /sconce

# ---- runtime ----
FROM debian:bookworm-slim
# git: clone git upstreams. ca-certificates: HTTPS to registries/git remotes.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /sconce /usr/local/bin/sconce

# Run unprivileged; CAS lives on a volume.
RUN useradd --system --uid 10001 sconce \
    && mkdir -p /var/lib/sconce/cas \
    && chown -R sconce /var/lib/sconce
USER sconce
VOLUME ["/var/lib/sconce/cas"]
EXPOSE 8080 8081

# DATABASE_URL, SCONCE_ADMIN_PASSWORD, SCONCE_SECRET_KEY come from the environment.
ENTRYPOINT ["sconce"]
CMD ["serve", \
     "--cas", "/var/lib/sconce/cas", \
     "--listen", "0.0.0.0:8080", \
     "--ui-listen", "0.0.0.0:8081", \
     "--base-url", "http://localhost:8080"]
