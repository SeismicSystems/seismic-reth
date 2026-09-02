# Seismic Viem tests

To install dependencies:

```bash
bun install
```

To run tests:

```bash
bun test
```

Note: These tests assume the .env is set up. See `.env.example` for an example.
The tests do not actually check the .env rn. run the tests with something like:
```bash
SRETH_ROOT=$SRETH_ROOT RETH_DATA_DIR=$RETH_DATA_DIR RETH_STATIC_FILES=$RETH_STATIC_FILES bun viem:test 
```