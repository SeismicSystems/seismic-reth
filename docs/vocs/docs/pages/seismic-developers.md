# Seismic Developer

#### Table of Contents

 - [Running a Local Full Node](#running-a-local-full-node)
   - [Build a Reth Docker Image](#build-a-reth-docker-image)
   - [Spin Up a Network of Nodes](#spin-up-a-network-of-nodes)
   - [Debugging](#debugging)

## Running a Local Full Node

### Build a Reth Docker Image

Add the ABSOLUTE file path to your SSH private key with GitHub as the value of the `src=` parameter when you run the following command. This is to build Reth's dependencies from Seismic's GitHub, if there are any.

```bash
docker buildx build --secret id=ssh_key,src=[ABSOLUTE_PATH_TO_YOUR_SSH_PK] -t seismic-reth:local .
```

1. Because we use multistage builds during the creation of the final image, the SSH key is only copied to the intermediate image, which means that the final image will not contain your SSH keys.
2. In production environments, we can use `docker secret` to pass the same SSH keys.

### Spin Up a Network of Nodes

We use `kurtosis` and [ethereum-package](https://github.com/ethpandaops/ethereum-package) to spin up a network of nodes.

```
kurtosis run --enclave seismic-local github.com/ethpandaops/ethereum-package --args-file network_params.yaml
```

To verify that the nodes are brought up, you should be able to see the corresponding containers.

* **vc-1**: Refers to Validator Client (VC). This is likely a Lighthouse validator client interacting with both the Reth execution client and Lighthouse beacon node for proposing and attesting blocks in Ethereum’s Proof of Stake consensus.
* **cl-1**: Refers to the Consensus Layer (CL). This is probably the Lighthouse beacon node responsible for maintaining consensus and communicating with the Reth execution client.
* **el-1**: Refers to the Execution Layer (EL). This is most likely the Reth execution client, which processes transactions, executes smart contracts, and maintains the Ethereum state.

In particular, the above command does the following:

1. Generates Execution Layer (EL) and Consensus Layer (CL) genesis information using [the Ethereum genesis generator](https://github.com/ethpandaops/ethereum-genesis-generator).
2. Configures and bootstraps a network of Ethereum nodes of *n* size using the genesis data generated above.
3. Spins up a [transaction spammer](https://github.com/MariusVanDerWijden/tx-fuzz) to send fake transactions to the network.
4. Spins up and connects a [testnet verifier](https://github.com/ethereum/merge-testnet-verifier).
5. Spins up a Grafana and Prometheus instance to observe the network.
6. Spins up a Blobscan instance to analyze blob transactions (EIP-4844).

For more information, please see the [ethereum-package](https://github.com/ethpandaops/ethereum-package) documentation. We might want to fork this package for Seismic for more customizable testing, especially when enclaves start to get involved.

### Debugging

You can run `docker exec -it [CONTAINER_ID] bash` to debug a specific container.

TODO: I don't think you can bring up more than one node using Kurtosis. There is currently a bug.