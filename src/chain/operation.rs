use serde::{Deserialize};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Operation {
    Operation(String),
    CustomJson(CustomJson),
    Unknown(Unknown),
}

#[derive(Debug, Deserialize)]
pub struct CustomJson {
    id: String,
    json: String,
    required_auths: Vec<String>,
    required_posting_auths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Unknown {}
