FROM debian:trixie-slim AS runtime
ARG SYSROOT

WORKDIR /app

# COPY --from=builder /app/target/release/attestation-server /usr/local/bin/attestation-server
# COPY --from=builder /sysroot /sysroot

COPY ${SYSROOT}/lib /sysroot/lib
COPY ./target/release/attestation-server /attestation-server
COPY ./attestation-server/entrypoint.sh /entrypoint.sh

RUN apt-get update \
    && apt-get install -y \
    ca-certificates

RUN apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* \
    && chmod +x /entrypoint.sh

ENV ROCKET_ENV=prod
ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_PORT=8000
ENV LD_LIBRARY_PATH=/sysroot/lib
ENV NVIDIA_VISIBLE_DEVICES=all

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
