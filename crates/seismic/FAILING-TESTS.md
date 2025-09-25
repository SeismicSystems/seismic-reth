## Unit tests

Summary [  80.170s] 2009 tests run: 1988 passed, 21 failed, 27 skipped
TRY 4 FAIL [   0.020s] reth-chainspec spec::tests::holesky_fork_ids
TRY 4 FAIL [   0.020s] reth-chainspec spec::tests::hoodi_fork_ids
TRY 4 FAIL [   0.365s] reth-chainspec spec::tests::latest_eth_mainnet_fork_id
TRY 4 FAIL [   0.417s] reth-chainspec spec::tests::mainnet_fork_ids
TRY 4 FAIL [   0.434s] reth-chainspec spec::tests::mainnet_hardfork_fork_ids
TRY 4 FAIL [   0.007s] reth-chainspec spec::tests::sepolia_fork_ids
TRY 4 FAIL [   0.007s] reth-chainspec spec::tests::sepolia_hardfork_fork_ids
TRY 4 FAIL [   0.329s] reth-chainspec spec::tests::test_hardfork_list_display_mainnet
TRY 4 FAIL [   0.637s] reth-chainspec spec::tests::timestamped_forks
TRY 4 FAIL [   0.345s] reth-provider writer::tests::bundle_state_state_root
TRY 4 FAIL [   0.325s] reth-seismic-chainspec tests::display_hardforks
TRY 4 FAIL [   0.007s] reth-seismic-forks tests::check_ethereum_hardforks_at_zero
TRY 4 FAIL [   0.183s] reth-seismic-primitives transaction::signed::SeismicTransactionSignedTests::proptest
TRY 4 FAIL [   0.656s] reth-stages stages::merkle::tests::execute_chunked_merkle
TRY 4 FAIL [   1.057s] reth-stages stages::merkle::tests::execute_clean_merkle
TRY 4 FAIL [   0.950s] reth-stages stages::merkle::tests::execute_merkle
TRY 4 FAIL [   0.595s] reth-stages stages::merkle::tests::execute_small_merkle
TRY 4 FAIL [   1.035s] reth-stages stages::merkle::tests::unwind_merkle
TRY 4 FAIL [   0.797s] reth-trie-parallel root::tests::random_parallel_root
TRY 4 FAIL [   0.011s] reth-trie-sparse trie::tests::sparse_trie_display
TRY 4 FAIL [   0.013s] reth-trie-sparse trie::tests::sparse_trie_remove_leaf

## Integration tests

Summary [ 408.113s] 326 tests run: 305 passed (1 slow), 21 failed, 12 skipped
TRY 4 FAIL [   1.546s] reth-e2e-test-utils::e2e_testsuite test_apply_with_import
TRY 4 FAIL [  84.567s] reth-node-ethereum::e2e p2p::test_long_reorg
TRY 4 FAIL [  14.926s] reth-node-ethereum::e2e rpc::test_flashbots_validate_v3
TRY 4 FAIL [  13.804s] reth-node-ethereum::e2e rpc::test_flashbots_validate_v4
TRY 4 FAIL [   1.152s] reth-rpc-e2e-tests::e2e_testsuite test_local_rpc_tests_compat
TRY 4 FAIL [  10.828s] reth-trie-db::fuzz_in_memory_nodes fuzz_in_memory_account_nodes
TRY 4 FAIL [   2.935s] reth-trie-db::proof holesky_deposit_contract_proof
TRY 4 FAIL [   2.782s] reth-trie-db::proof mainnet_genesis_account_proof
TRY 4 FAIL [   1.440s] reth-trie-db::proof mainnet_genesis_account_proof_nonexistent
TRY 4 FAIL [   4.314s] reth-trie-db::proof testspec_empty_storage_proof
TRY 4 FAIL [   2.571s] reth-trie-db::proof testspec_proofs
TRY 4 FAIL [   3.491s] reth-trie-db::trie account_and_storage_trie
TRY 4 FAIL [   2.423s] reth-trie-db::trie account_trie_around_extension_node
TRY 4 FAIL [   1.566s] reth-trie-db::trie account_trie_around_extension_node_with_dbtrie
TRY 4 FAIL [   0.857s] reth-trie-db::trie arbitrary_state_root
TRY 4 FAIL [   0.965s] reth-trie-db::trie arbitrary_state_root_with_progress
TRY 4 FAIL [   2.559s] reth-trie-db::trie arbitrary_storage_root
TRY 4 FAIL [  10.377s] reth-trie-db::trie fuzz_state_root_incremental
TRY 4 FAIL [   1.783s] reth-trie-db::trie test_empty_account
TRY 4 FAIL [   0.843s] reth-trie-db::trie test_storage_root
