use std::fs;
use hive_rs::chain::operation::{Operation};
use hive_rs::client::condenser::{CondenserClient};
use httpmock::prelude::{MockServer, POST};

#[tokio::test]
async fn retrieve_block() {
    let server = MockServer::start();
    let payload = fs::read_to_string("tests/resources/get_block.json").expect("Unable to read file");
    let condenser_block_mock = server.mock(|when, then| {
        when.method(POST);
        then.status(200)
            .header("content-type", "applications/json")
            .body(payload);
    });
    let mut client = CondenserClient::new(vec![server.base_url()], None);
    let response = client.get_block(64522225).await;
    let block = response.ok().unwrap();
    for transaction in block.transactions {
        for operation in transaction.operations {
            let (name, content) = operation;
            let is_custom_json = match content {
                Operation::CustomJson(_) => { true },
                _ => { false }
            };
            assert_eq!(is_custom_json, name == "custom_json");
        }
    }
    condenser_block_mock.assert();
}

#[tokio::test]
async fn retrieve_properties() {
    let server = MockServer::start();
    let payload = fs::read_to_string("tests/resources/get_global_props.json").expect("Unable to read file");
    let condenser_props_mock = server.mock(|when, then| {
        when.method(POST);
        then.status(200)
            .header("content-type", "applications/json")
            .body(payload);
    });
    let mut client = CondenserClient::new(vec![server.base_url()], None);
    let response = client.get_global_properties().await;
    let properties = response.ok().unwrap();
    assert_eq!(64551284, properties.head_block_number);
    assert_eq!(64551267, properties.last_irreversible_block_num);
    condenser_props_mock.assert();
}


