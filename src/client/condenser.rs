use reqwest::{Error};
use crate::chain::block::Block;
use crate::chain::global_properties::GlobalProperties;
use crate::client::hive_client::{HiveClient};

const GET_BLOCK: &str = "condenser_api.get_block";
const GET_GLOBAL_PROPERTIES: &str = "condenser_api.get_dynamic_global_properties";

pub struct CondenserClient {
    hive_client: HiveClient,
}

impl CondenserClient {
    pub fn new(hosts: Vec<String>, max_retry: Option<u8>) -> CondenserClient {
        let hive_client = HiveClient::new(hosts, max_retry);
        Self { hive_client }
    }

    pub async fn get_block(&mut self, block_num: u32) -> Result<Block, Error> {
        self.hive_client.post(GET_BLOCK.to_string(), Some(vec![block_num])).await
    }

    pub async fn get_global_properties(&mut self) -> Result<GlobalProperties, Error> {
        self.hive_client.post(GET_GLOBAL_PROPERTIES.to_string(), None).await
    }
}
