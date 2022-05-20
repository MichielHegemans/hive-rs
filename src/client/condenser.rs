use reqwest::{Error, Response};
use serde::{Deserialize};
use crate::chain::block::Block;
use crate::chain::global_properties::GlobalProperties;
use crate::client::client::{HiveClient};

const GET_BLOCK: &str = "condenser_api.get_block";
const GET_GLOBAL_PROPERTIES: &str = "condenser_api.get_dynamic_global_properties";

pub struct CondenserClient {
    hive_client: HiveClient,
}

impl CondenserClient {
    fn new(hosts: Vec<String>) -> CondenserClient {
        let hive_client = HiveClient::new(hosts);
        Self { hive_client }
    }

    async fn get_block(&self, block_num: u32) -> Result<Block, Error> {
        self.hive_client.post(GET_BLOCK.to_string(), vec![block_num]).await
    }

    async fn get_global_properties(&self) -> Result<GlobalProperties, Error> {
        self.hive_client.post(GET_GLOBAL_PROPERTIES.to_string(), vec![]).await
    }
}

/*
    TODO: These tests should not hit live apis...
*/
#[cfg(test)]
mod tests {
    use crate::client::condenser::{CondenserClient};

    #[tokio::test]
    async fn retrieve_block() {
        let client = CondenserClient::new(vec!["https://api.hive.blog".to_string()]);
        let response = client.get_block(64522225).await;
        let block = response.ok().unwrap();
        println!("deserialized = {:?}", block);
    }

    #[tokio::test]
    async fn retrieve_properties() {
        let client = CondenserClient::new(vec!["https://api.hive.blog".to_string()]);
        let response = client.get_global_properties().await;
        let properties = response.ok().unwrap();
        println!("deserialized = {:?}", properties);
    }
}