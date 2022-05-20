use serde::{Deserialize};
use crate::chain::operation::Operation;

#[derive(Debug, Deserialize)]
pub struct Transaction {
    ref_block_num: u32,
    ref_block_prefix: u32,
    expiration: String,
    transaction_id: String,
    transaction_num: u32,
    block_num: u32,
    operations: Vec<Vec<Operation>>,
    signatures: Vec<String>,
}