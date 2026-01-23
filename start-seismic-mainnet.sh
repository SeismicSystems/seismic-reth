#!/bin/bash

# Seismic Mainnet Reth Startup Script
# This script starts reth configured for Seismic mainnet with Engine API enabled
# Usage: ./start-seismic-mainnet.sh [--debug] [--clear] [additional args...]

set -e

# Parse flags
DEBUG_MODE=false
CLEAR_DATA=false
ARGS=()

for arg in "$@"; do
    case $arg in
    --debug)
        DEBUG_MODE=true
        shift
        ;;
    --clear)
        CLEAR_DATA=true
        shift
        ;;
    *)
        ARGS+=("$arg")
        ;;
    esac
done

# Configuration
DATA_DIR="$HOME/.reth/seismic-mainnet"
JWT_SECRET_PATH="$DATA_DIR/jwt.hex"
IPC_PATH="/tmp/reth-engine.ipc"
ENGINE_PORT=8551
HTTP_PORT=8545
WS_PORT=8546
P2P_PORT=30303
GENESIS_DIR="crates/seismic/chainspec/res/genesis"
GENESIS_FILE="$GENESIS_DIR/dev.json"
GENESIS_URL="https://testnet-benchmarking.s3.us-west-2.amazonaws.com/bench_dev.json"

# Debug configuration
if [ "$DEBUG_MODE" = true ]; then
    LOG_LEVEL="debug"
    LOG_TARGETS="reth::cli,reth_node_core,reth_engine_tree,reth_evm,reth_provider,reth_blockchain_tree,reth_seismic_evm,reth_seismic_node,reth_enclave,engine::tree"
else
    LOG_LEVEL="info"
    LOG_TARGETS=""
fi

# Clear data directory if requested
if [ "$CLEAR_DATA" = true ]; then
    if [ -d "$DATA_DIR" ]; then
        echo "Clearing data directory: $DATA_DIR"
        rm -rf "$DATA_DIR"
    fi
fi

# Create data directory if it doesn't exist
mkdir -p "$DATA_DIR"

# Download genesis file if it doesn't exist
if [ ! -f "$GENESIS_FILE" ]; then
    echo "Genesis file not found, downloading from $GENESIS_URL"
    mkdir -p "$GENESIS_DIR"
    if command -v curl >/dev/null 2>&1; then
        curl -o "$GENESIS_FILE" "$GENESIS_URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$GENESIS_FILE" "$GENESIS_URL"
    else
        echo "Error: Neither curl nor wget found. Please install one of them or manually download:"
        echo "$GENESIS_URL -> $GENESIS_FILE"
        exit 1
    fi
    echo "Genesis file downloaded successfully"
fi

echo "Starting Seismic mainnet node..."
echo "Data directory: $DATA_DIR"
echo "Engine API: http://localhost:$ENGINE_PORT"
echo "Engine IPC: $IPC_PATH"
echo "HTTP RPC: http://localhost:$HTTP_PORT"
echo "WebSocket RPC: ws://localhost:$WS_PORT"
echo "Metrics: http://localhost:9001/metrics"
echo "Log level: $LOG_LEVEL"

# Build logging arguments
LOG_ARGS=()
if [ "$DEBUG_MODE" = true ]; then
    LOG_ARGS+=(--log.stdout.filter "$LOG_TARGETS=$LOG_LEVEL")
    LOG_ARGS+=(--log.file.filter "$LOG_TARGETS=$LOG_LEVEL")
    LOG_ARGS+=(-vvvv) # Very verbose
else
    LOG_ARGS+=(--log.stdout.filter "$LOG_LEVEL")
    LOG_ARGS+=(-vvv) # Info level
fi

# Add environment variable for more detailed engine logs
export RUST_LOG="error,engine::tree=debug,reth_engine_tree=debug,reth_seismic_evm=debug,reth_evm=debug,reth_evm_ethereum=debug,reth_seismic_node=debug,reth_seismic_primitives=debug,reth_payload=debug"

# Start seismic-reth with Seismic mainnet configuration
# Note: Using seismic-reth binary instead of standard reth
exec cargo run --bin seismic-reth --release -- node \
    --datadir "$DATA_DIR" \
    --port "$P2P_PORT" \
    --http \
    --http.port "$HTTP_PORT" \
    --http.addr 0.0.0.0 \
    --http.corsdomain "*" \
    --ws \
    --ws.port "$WS_PORT" \
    --ws.addr 0.0.0.0 \
    --auth-ipc \
    --auth-ipc.path "$IPC_PATH" \
    --authrpc.addr 0.0.0.0 \
    --discovery.port "$P2P_PORT" \
    --metrics 0.0.0.0:9001 \
    --enclave.mock-server \
    --enclave.endpoint-port 1477 \
    --rpc.max-connections 40000 \
    --txpool.pending-max-count 40000 \
    --txpool.pending-max-size 160 \
    "${LOG_ARGS[@]}" \
    "${ARGS[@]}"
