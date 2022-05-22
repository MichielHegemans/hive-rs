use serde::{Deserialize};

#[derive(Debug, Deserialize)]
pub struct GlobalProperties {
    pub last_irreversible_block_num: u32,
    pub head_block_number: u32,
}
