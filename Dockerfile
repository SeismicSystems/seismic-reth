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
RUN --mount=type=ssh cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked --bin seismic-reth

# Copy the binary to a temporary location
RUN cp /app/target/$BUILD_PROFILE/seismic-reth /app/seismic-reth

# Use Ubuntu as the runtime image
FROM ubuntu:latest AS runtime
WORKDIR /app

# Copy reth over from the build stage
COPY --from=builder /app/seismic-reth /usr/local/bin

# Copy license files
COPY LICENSE-* ./

# Define the ENTRYPOINT to run the reth node with the specified arguments
ENV HTTP_PORT=8545
ENV WS_PORT=8546
ENV AUTHRPC_PORT=8551
ENV METRICS_PORT=9001
ENV PEER_PORT=30303
ENV DISCOVERY_PORT=30303

# Expose the necessary ports
EXPOSE \
    $HTTP_PORT \
    $WS_PORT \
    $AUTHRPC_PORT \
    $METRICS_PORT \
    $PEER_PORT \
    $DISCOVERY_PORT/udp


ENTRYPOINT /usr/local/bin/seismic-reth node \
            --dev \
            -vvvv \
            --http \
            --http.addr 0.0.0.0 \
            --http.port $HTTP_PORT \
            --ws.port $WS_PORT \
            --authrpc.port $AUTHRPC_PORT \
            --authrpc.addr 0.0.0.0 \
            --port $PEER_PORT \
            --discovery.port $DISCOVERY_PORT \
            --metrics $METRICS_PORT
