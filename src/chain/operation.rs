use serde::{Deserialize};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Operation {
    CustomJson(CustomJson),
    Unknown(Unknown),
}

#[derive(Debug, Deserialize)]
pub struct CustomJson {
    pub id: String,
    pub json: String,
    pub required_auths: Vec<String>,
    pub required_posting_auths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Unknown {}
