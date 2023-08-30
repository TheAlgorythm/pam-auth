FROM rust:slim-bookworm as builder
WORKDIR /usr/src/pam-auth
RUN apt update && apt install -y libpam-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock .
COPY pin-data pin-data
COPY pin-gen pin-gen
COPY pam-utils pam-utils
COPY pam-pin pam-pin
COPY pam-direct-fallback pam-direct-fallback

RUN cargo build --release
# RUN cargo build --release --no-default-features

FROM debian:bookworm-slim
RUN apt update && apt install -y pamtester && rm -rf /var/lib/apt/lists/*

RUN mkdir /etc/security/direct-fallback
COPY ressources/pin-test /etc/pam.d/
COPY ressources/direct-fallback-test /etc/pam.d/
COPY ressources/sample-pins.toml /etc/security/pins.toml
COPY ressources/container_sh_history /root/.bash_history

COPY --from=builder /usr/src/pam-auth/target/release/pin-gen /usr/local/bin/
COPY --from=builder /usr/src/pam-auth/target/release/libpam_pin.so /lib/security/pam_pin.so
COPY --from=builder /usr/src/pam-auth/target/release/libpam_direct_fallback.so /lib/security/pam_direct_fallback.so
