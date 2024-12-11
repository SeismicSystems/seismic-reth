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
COPY Cargo.toml Cargo.lock deny.toml Makefile ./
RUN cargo chef prepare --recipe-path recipe.json

# Build the application
FROM chef AS builder
# Setting up SSH for GitHub access
RUN mkdir -p -m 0700 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
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

ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
# Build dependencies
RUN --mount=type=ssh cargo chef cook --profile $BUILD_PROFILE --features "$FEATURES" --recipe-path recipe.json

# Build the application binary
COPY ./bin/ ./bin/
COPY ./crates/ ./crates/
COPY ./testing/ ./testing/
COPY ./examples/ ./examples/
COPY Cargo.toml Cargo.lock deny.toml Makefile ./
RUN --mount=type=ssh cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked --bin reth

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
COPY docker/execution_genesis.json ./genesis.json
COPY docker/nodekey ./nodekey
COPY docker/jwtsecret ./jwt.hex

# Expose the necessary ports
EXPOSE 8551 \
       8545 \
       30303 \
       30303/udp \
       8546 \
       6060

# Define the ENTRYPOINT to run the reth node with the specified arguments
ENV AUTHRPC_PORT=8551
ENV HTTP_PORT=8545
ENV PEER_PORT=30303
ENV DISCOVERY_PORT=30303
ENV WS_PORT=8546
ENV METRICS_PORT=6060

ENTRYPOINT /usr/local/bin/reth node \
            -vvv \
            --tee.mock-server \
            # --dev --dev.block-max-transactions 1 \
            --http \
            --http.addr 0.0.0.0 \
            --http.port $HTTP_PORT \
            --http.api "eth,net,web3,trace,rpc,debug,txpool" \ 
            --port $PEER_PORT \
            --discovery.port $DISCOVERY_PORT \
            --ws.port $WS_PORT \
            --ws.addr 0.0.0.0 \
            --metrics $METRICS_PORT \
            --authrpc.port $AUTHRPC_PORT \
            --authrpc.addr 0.0.0.0 \
            --authrpc.jwtsecret /app/jwt.hex \
            --chain ./genesis.json \
            --p2p-secret-key ./nodekey \
            --trusted-peers enode://f435477cdb474dcb5903cf9df6b9b39be66b71308c5ade95a4a7780be180d22ba847f44ae7adbfb484e9d64cf22a4f19a25ac72fd83a7eef8062ca6528388528@10.186.73.102:30303,enode://3116e85de20404db0c64a75b72afffa90e914b2e7c5e7141c445e03fd6702c3da986e23ea554b87c1b6feb58e2423a8588ec17b9a635f3fa0ab2c0b341bb0cf5@10.186.73.101:30303 \
            --bootnodes enode://f435477cdb474dcb5903cf9df6b9b39be66b71308c5ade95a4a7780be180d22ba847f44ae7adbfb484e9d64cf22a4f19a25ac72fd83a7eef8062ca6528388528@10.186.73.102:30303,enode://3116e85de20404db0c64a75b72afffa90e914b2e7c5e7141c445e03fd6702c3da986e23ea554b87c1b6feb58e2423a8588ec17b9a635f3fa0ab2c0b341bb0cf5@10.186.73.101:30303 
