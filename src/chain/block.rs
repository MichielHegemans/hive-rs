use serde::{Deserialize};
use crate::chain::transaction::Transaction;

#[derive(Debug, Deserialize)]
pub struct Block {
    previous: String,
    timestamp: String,
    witness: String,
    transaction_merkle_root: String,
    witness_signature: String,
    block_id: String,
    signing_key: String,
    transaction_ids: Vec<String>,
    transactions: Vec<Transaction>,
}