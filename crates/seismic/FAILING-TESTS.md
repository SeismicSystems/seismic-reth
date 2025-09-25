## Unit tests

Summary [  61.366s] 2009 tests run: 1999 passed, 10 failed, 27 skipped
TRY 4 FAIL [   0.654s] reth-stages stages::merkle::tests::execute_chunked_merkle
TRY 4 FAIL [   1.048s] reth-stages stages::merkle::tests::execute_clean_merkle
TRY 4 FAIL [   0.954s] reth-stages stages::merkle::tests::execute_merkle
TRY 4 FAIL [   0.576s] reth-stages stages::merkle::tests::execute_small_merkle
TRY 4 FAIL [   1.039s] reth-stages stages::merkle::tests::unwind_merkle
TRY 4 FAIL [   0.827s] reth-trie-parallel root::tests::random_parallel_root
TRY 4 FAIL [   0.016s] reth-trie-sparse trie::tests::sparse_trie_display
TRY 4 FAIL [   0.013s] reth-trie-sparse trie::tests::sparse_trie_remove_leaf

### Need full fixing
- Refactoring envelope: TRY 4 FAIL [   0.190s] reth-seismic-primitives transaction::signed::SeismicTransactionSignedTests::proptest


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
