# syntax=docker/dockerfile:1
# Single-binary sconce: one `serve` process runs the Composer wire API, the
# admin UI, and the in-process mirror worker. Postgres is the only dependency.

# ---- build ----
# Pinned to the workspace MSRV (rust-toolchain.toml). rustls everywhere (sqlx,
# ureq) so the build needs no OpenSSL/native libs.
FROM rust:1.96-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin sconce

# ---- runtime ----
FROM debian:bookworm-slim
# git: clone git upstreams. ca-certificates: HTTPS to registries/git remotes.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/sconce /usr/local/bin/sconce

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
