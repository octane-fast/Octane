FROM rust:1-alpine AS builder
WORKDIR /usr/src/app
RUN apk add musl-dev pkgconfig
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/src/app/target/release/octusd-oracle /usr/local/bin/octusd-oracle
CMD ["octusd-oracle"]
