# Use cargo-chef for build caching
FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

LABEL org.opencontainers.image.source=https://github.com/SeismicSystems/seismic-reth
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config

# Build the cargo-chef plan
FROM chef AS planner

COPY ./bin/ ./bin/
COPY ./crates/ ./crates/
COPY ./testing/ ./testing/
COPY ./examples/ ./examples/
COPY Cargo.toml Cargo.lock deny.toml Makefile .
# COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Build the application
FROM chef AS builder
# Setting up SSH for GitHub access
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

# Build dependencies
RUN cargo chef cook --profile $BUILD_PROFILE --features "$FEATURES" --recipe-path recipe.json

# Build the application binary
COPY ./bin/ ./bin/
COPY ./crates/ ./crates/
COPY ./testing/ ./testing/
COPY ./examples/ ./examples/
COPY Cargo.toml Cargo.lock deny.toml Makefile .
RUN cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked --bin reth

# Copy the binary to a temporary location
RUN cp /app/target/$BUILD_PROFILE/reth /app/reth

# Use Ubuntu as the runtime image
FROM ubuntu:latest AS runtime
WORKDIR /app

# Copy reth over from the build stage
COPY --from=builder /app/reth /usr/local/bin

# Copy license files
COPY LICENSE-* ./

# Set up the reth configs
# Copy the files from the docker folder to the container's directory
COPY docker/genesis.json ./genesis.json
COPY docker/nodekey ./nodekey
COPY docker/jwtsecret ./jwt.hex

# Expose the necessary ports
EXPOSE 8551 \
       8000 \
       8545 \
       30303 \
       30303/udp \
       8546 \
       6060

# Define the ENTRYPOINT to run the reth node with the specified arguments
ENV AUTHRPC_PORT=8551
ENV HTTP_PORT=8000
ENV PEER_PORT=30303
ENV DISCOVERY_PORT=30303
ENV WS_PORT=8546
ENV METRICS_PORT=6060

ENTRYPOINT /usr/local/bin/reth node \
            -vvvvv --authrpc.port $AUTHRPC_PORT \
            --http.port $HTTP_PORT --port $PEER_PORT \
            --discovery.port $DISCOVERY_PORT \
            --ws.port $WS_PORT \
            --metrics $METRICS_PORT \
            --authrpc.jwtsecret /app/jwt.hex \
            --chain ./genesis.json \
            --p2p-secret-key ./nodekey
