use serde::{Deserialize};

#[derive(Debug, Deserialize)]
pub struct GlobalProperties {
    last_irreversible_block_num: u32,
    head_block_number: u32,
}
