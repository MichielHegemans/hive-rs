use serde::{Deserialize};
use crate::chain::operation::Operation;

#[derive(Debug, Deserialize)]
pub struct Transaction {
    pub ref_block_num: u32,
    pub ref_block_prefix: u32,
    pub expiration: String,
    pub transaction_id: String,
    pub transaction_num: u32,
    pub block_num: u32,
    pub operations: Vec<(String, Operation)>,
    pub signatures: Vec<String>,
}