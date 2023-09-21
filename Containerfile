FROM rust:slim-bookworm as builder
WORKDIR /usr/src/pam-auth
RUN apt update && apt install -y libpam-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock .
COPY pin-data/Cargo.toml pin-data/
COPY pin-gen/Cargo.toml pin-gen/
COPY pam-utils/Cargo.toml pam-utils/
COPY pam-pin/Cargo.toml pam-pin/
COPY pam-direct-fallback/Cargo.toml pam-direct-fallback/


RUN mkdir pam-utils/src pam-pin/src pin-data/src pin-gen/src pam-direct-fallback/src \
    && touch pam-utils/src/lib.rs pam-pin/src/lib.rs pin-data/src/lib.rs \
      pin-gen/src/main.rs pam-direct-fallback/src/lib.rs \
    && cargo fetch

COPY pin-data pin-data
COPY pin-gen pin-gen
COPY pam-utils pam-utils
COPY pam-pin pam-pin
COPY pam-direct-fallback pam-direct-fallback

# RUN cargo fetch
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
