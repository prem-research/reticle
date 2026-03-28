# syntax=docker/dockerfile:1.7

# FROM rust:slim-bookworm AS builder
# WORKDIR /app


# COPY ${SYSROOT} /sysroot

# COPY Cargo.toml Cargo.lock ./

# COPY attestation-server/Cargo.toml attestation-server/Cargo.toml
# COPY snp-attest/Cargo.toml snp-attest/Cargo.toml
# COPY libattest/Cargo.toml libattest/Cargo.toml
# COPY nvidia-attest/Cargo.toml nvidia-attest/Cargo.toml
# COPY prem-rs/Cargo.toml prem-rs/Cargo.toml

# COPY attestation-server/src attestation-server/src
# COPY snp-attest/src snp-attest/src
# COPY libattest/src libattest/src
# COPY nvidia-attest/src nvidia-attest/src
# COPY prem-rs/src prem-rs/src

# RUN env -u SYSROOT -u PKG_CONFIG_SYSROOT_DIR \
#     RUSTFLAGS="-L${SYSROOT}/lib" \
#     cargo build --release -p attestation-server --no-default-features --features "${FEATURES}"

FROM debian:bookworm-slim AS runtime
ARG SYSROOT

WORKDIR /app

# COPY --from=builder /app/target/release/attestation-server /usr/local/bin/attestation-server
# COPY --from=builder /sysroot /sysroot

COPY ${SYSROOT}/lib /sysroot/lib
COPY ./target/release/attestation-server /attestation-server

RUN apt-get update \
    && apt-get install -y \
        ca-certificates

RUN apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

ENV ROCKET_ENV=prod
ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_PORT=8000
ENV LD_LIBRARY_PATH=/sysroot/lib
ENV NVIDIA_VISIBLE_DEVICES=all

EXPOSE 8000

CMD ["/attestation-server"]
