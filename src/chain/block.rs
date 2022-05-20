use serde::{Deserialize};
use crate::chain::transaction::Transaction;

#[derive(Debug, Deserialize)]
pub struct Block {
    pub previous: String,
    pub timestamp: String,
    pub witness: String,
    pub transaction_merkle_root: String,
    pub witness_signature: String,
    pub block_id: String,
    pub signing_key: String,
    pub transaction_ids: Vec<String>,
    pub transactions: Vec<Transaction>,
}