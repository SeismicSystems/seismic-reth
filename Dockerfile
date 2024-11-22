FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

LABEL org.opencontainers.image.source=https://github.com/SeismicSystems/seismic-reth
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config

# Builds a cargo-chef plan
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# Setting up ssh for github
RUN mkdir -p -m 0700 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN --mount=type=secret,id=ssh_key \
    cp /run/secrets/ssh_key ~/.ssh/id_ed25519 && \
    chmod 600 ~/.ssh/id_ed25519

COPY --from=planner /app/recipe.json recipe.json

# Build profile, release by default
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE=$BUILD_PROFILE

# Extra Cargo flags
ARG RUSTFLAGS=""
ENV RUSTFLAGS="$RUSTFLAGS"

# Extra Cargo features
ARG FEATURES=""
ENV FEATURES=$FEATURES

# Builds dependencies
RUN cargo chef cook --profile $BUILD_PROFILE --features "$FEATURES" --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked --bin reth

# ARG is not resolved in COPY so we have to hack around it by copying the
# binary to a temporary location
RUN cp /app/target/$BUILD_PROFILE/reth /app/reth

# Use Ubuntu as the release image
FROM ubuntu AS runtime
WORKDIR /app

# Copy reth over from the build stage
COPY --from=builder /app/reth /usr/local/bin

# Copy licenses
COPY LICENSE-* ./

EXPOSE 30303 30303/udp 9001 8545 8546
ENTRYPOINT ["/usr/local/bin/reth"]
