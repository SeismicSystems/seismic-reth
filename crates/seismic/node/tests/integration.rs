use assert_cmd::{assert, Command};
use reqwest::Client;
use serde_json::{json, Value};
use std::{thread, time::Duration};

// this is the same test as basic.rs but with actual RPC calls and standalone reth instance
#[tokio::test]
async fn test_seismic_reth_rpc() {
    const RETH_RPC_URL: &str = "http://127.0.0.1:8545";
    // Step 1: Start the binary
    let cmd = Command::cargo_bin("seismic-reth").unwrap();
    let cmd_str = cmd.get_program().to_str().unwrap();
    let mut child = tokio::process::Command::new(cmd_str)
        .arg("node")
        .arg("--datadir")
        .arg("./tmp/reth")
        .arg("--dev")
        .arg("--dev.block-max-transactions")
        .arg("1")
        .arg("--tee.mock-server")
        .arg("-vvvv")
        .spawn()
        .expect("Failed to start the binary");

    // Step 2: Allow the binary some time to start
    thread::sleep(Duration::from_secs(5));

    // Step 3: Send RPC calls
    let client = Client::new();

    // Deploy the contract
    let deploy_tx = json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": ["0x4af90302820539808504a817c800830927c08080b902ac224bf76b7b416cf7956e92b4f2ddec31ce1879aeaa1c57f3e7eb12d4be60cd5b63bcd737ad8d90447dbb381900ba80e4a70fe4aef31d0138e4c215091a3977c078a69c1451e350bd07b2dfe53442e205e2a3c94d5a58e642839278540bcc7251712b78fa2726865b480c3df2b2b6adaef8795d4c714caac3b98084ce3c874a17ea3eb365f1405b989e1b3f000e8d031e3bd400a347b1fadb4fb50abb7a1445f75e29204c3f096e4a79ed1b5b8b1aeffb3ef6ba37ad2cb2db9709405c441657f7ea7717536c8836c85a5c57c3c9c29e2dfbb04297c6eaa535a2511f4f44be2da3e54f6c832b09e9d9abb09ea1271a2d60bbac825175ae82bf32aa4a34d02bf8f0903ca4efb4fb55798ba6e18b234ea6562bf168909e0fb69bf3473463f8dc848e577b2d88d1701fc47802fb26ed19b046c60df13a21021e10e1356a72e43db71ebaba30d77697670878ff26e34f7802df5d376c8bf8eab9162852fa5b699c3c6a2b788e5f5ebcf31000e4e97ff39fb1df9e45a6a4b26a986182d14238b7551e2fd07a74618204f83e02d645b8cb81aef520103da6c1a3a46008a512e6d8117eef7d4f704d28ffca8121062e6ce0be9ea267f3a5f9b79015fbd02a0d782079cdb0aa61e35c147454290cdcca8ea572ea46c0b470d1fc117761704631e68f949870bac6355c4af990526cc3f3bc2d2a12024810004b5c374aa58a4ca4827e21caf897400476e4e7f790005708ec9cf1edb8920e8d2f3b67bf01378a85155d9c134fe6ae41133cffaadc61092117f13eb0593d3291214c4468a49bbee78a9c8e134e9c7570310f1d339f4232ed5e003fb5a2bcf25afabd309667778e1eca0f9568ab377bf47be95076e7812031711835fb480a21d3d2a35839681274bb15e4f2b5850b786eaa3d207816661264fdb7b708d7ffdcb3afcae166a1130f3e78991c7bb0788488c4521539cb1106bc6380a01adb4764b8125840e827803d82c0d30609af66b5a0860d6be558c237d0b65deca05ab4580e88cf2798404e75f2df18248ed1c7ca3161a1c56009b0dedee8e9ff0e"],
        "id": 1
    });

    let deploy_response = client
        .post(RETH_RPC_URL)
        .json(&deploy_tx)
        .send()
        .await
        .expect("Failed to send deploy transaction");

    let deploy_result: serde_json::Value = deploy_response.json().await.unwrap();
    println!("Deploy Result: {:?}", deploy_result);
    assert!(
        deploy_result["result"] ==
            "0x3eff537258c5c3c16fa520bea178171a0941814e36a3d88b0a9e683a6b34813e"
    );
    thread::sleep(Duration::from_secs(1));

    // Get the transaction receipt
    let receipt_tx = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": ["0x3eff537258c5c3c16fa520bea178171a0941814e36a3d88b0a9e683a6b34813e"],
        "id": 1
    });

    let receipt_response = client
        .post(RETH_RPC_URL)
        .json(&receipt_tx)
        .send()
        .await
        .expect("Failed to get transaction receipt");
    let receipt_result: Value = receipt_response.json().await.unwrap();
    println!("Transaction Receipt: {:?}", receipt_result);
    assert!(receipt_result["result"]["status"] == "0x1");

    // Step 1: Make sure the code of the contract is deployed
    let get_code = json!({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": ["0x5fbdb2315678afecb367f032d93f642f64180aa3", "latest"],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&get_code)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    println!("eth_getCode Response: {:?}", response);
    assert!(response["result"] == "0x608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806324a7f0b71461004357806343bd0d701461005f578063d09de08a1461007d575b5f5ffd5b61005d600480360381019061005891906100f6565b610087565b005b610067610090565b604051610074919061013b565b60405180910390f35b6100856100a7565b005b805f8190b15050565b5f600160025fb06100a19190610181565b14905090565b5f5f81b0809291906100b8906101de565b919050b150565b5f5ffd5b5f819050919050565b6100d5816100c3565b81146100df575f5ffd5b50565b5f813590506100f0816100cc565b92915050565b5f6020828403121561010b5761010a6100bf565b5b5f610118848285016100e2565b91505092915050565b5f8115159050919050565b61013581610121565b82525050565b5f60208201905061014e5f83018461012c565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61018b826100c3565b9150610196836100c3565b9250826101a6576101a5610154565b5b828206905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6101e8826100c3565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff820361021a576102196101b1565b5b60018201905091905056fea2646970667358221220ea421d58b6748a9089335034d76eb2f01bceafe3dfac2e57d9d2e766852904df64736f6c63782c302e382e32382d646576656c6f702e323032342e31322e392b636f6d6d69742e39383863313261662e6d6f64005d");

    // Step 2: eth_call to check the parity. Should be 0
    let eth_call = json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": ["0x4af87c820539018504a817c800830927c0945fbdb2315678afecb367f032d93f642f64180aa380942ca1d79749ef5170d6288dd66b8f61a0fa1a191001a0ada20ce02c6dd171ebef146f8dc4a26b4566a06b38fa8e78450046cf0d822229a04ab135fea2b037f9955c0259fca051d704d9b60a2d7904eaa610dfcad1058a77"],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&eth_call)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    println!("eth_call Response (parity 0): {:?}", response);
    assert!(
        response["result"] == "0x0000000000000000000000000000000000000000000000000000000000000000"
    );

    // Step 3: Send transaction to set suint
    let send_transaction = json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": ["0x4af89c820539018504a817c800830927c0945fbdb2315678afecb367f032d93f642f64180aa380b44bbb2a50b252f2fb7885ddf93294c66944d5a81e89116220f7d473ccac13a62be7763c95bab70690dfaf6ddc63a39c7c37e7dadd01a054feefb5a39d92b0b78d7f5e47b671fe9d52dbc85e6abef98cc29f7f055006c9a02d1ce83ef787d0c6572eb7bcaaae8c435797792d65ea18d2e4bfa67b63f94000"],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&send_transaction)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    println!("eth_sendRawTransaction Response: {:?}", response);
    assert!(
        response["result"] == "0x71bc51cfab4055bc61d80770ff5be6c34096b7a89b56579ccc5ad939eaed0bb7"
    );
    thread::sleep(Duration::from_secs(1));

    // Step 4: Get the transaction receipt
    let get_receipt = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionReceipt",
        "params": ["0x71bc51cfab4055bc61d80770ff5be6c34096b7a89b56579ccc5ad939eaed0bb7"],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&get_receipt)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    println!("eth_getTransactionReceipt Response: {:?}", response);
    assert!(response["result"]["status"] == "0x1");

    // Step 5: Final eth_call to check the parity. Should be 1
    let eth_call_final = json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": ["0x4af87c820539028504a817c800830927c0945fbdb2315678afecb367f032d93f642f64180aa380947674834b4f14099e8f581293b6c3d2dcd890716001a0eee7ffc97e7329ed015df8c248ca2df11d6cc50893ad858f746754436e1d2f44a04bcbe43de02148e73f4d78a30f7783cc684947f95e4b684a88adbbe748ad4de1"],
        "id": 1
    });

    let response: Value = client
        .post(RETH_RPC_URL)
        .json(&eth_call_final)
        .send()
        .await
        .expect("Failed to get code")
        .json()
        .await
        .expect("Failed to parse code");
    assert!(
        response["result"] == "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    println!("eth_call Response (parity 1): {:?}", response);

    // kill the process
    if let Err(e) = child.kill().await {
        if e.kind() == std::io::ErrorKind::InvalidInput {
            eprintln!("Process was already terminated.");
        } else {
            eprintln!("Failed to kill process: {}", e);
        }
    } else {
        println!("Process killed successfully.");
    }
}
