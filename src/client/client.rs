use reqwest::{Client, Error};
use serde::{Serialize, Deserialize};
use serde::de::{DeserializeOwned};

pub struct HiveClient {
    host: Vec<String>,
    current_host: String,
    client: Client,
}

impl HiveClient {

    /*
        TODO: validate user gives array containing at least one host.
    */
    pub fn new(host: Vec<String>) -> HiveClient {
        let current_host = host.get(0).unwrap().to_string();
        let client = Client::new();
        Self { host, current_host, client }
    }

    /*
        TODO: switch current host on network issues.
        TODO: add retry.
    */
    pub async fn post<T>(&self, method: String, params: Vec<u32>) -> Result<T, Error>
        where T: DeserializeOwned, {
        let payload = Request::new(method, params);
        let response = self.client.post(&self.current_host)
            .body(payload.to_string())
            .send()
            .await;
        match response {
            Ok(res) => {
                let body = res.text().await.unwrap();
                let output: Response<T> = serde_json::from_str(&body).unwrap();
                Ok(output.result)
            },
            Err(err) => Err(err),
        }
    }
}

#[derive(Serialize)]
pub struct Request {
    jsonrpc: String,
    method: String,
    params: Vec<u32>,
    id: u32,
}

impl Request {
    pub fn new(method: String, params: Vec<u32>) -> Request {
        Self {
            jsonrpc: "2.0".to_string(),
            method,
            params,
            id: 0
        }
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}


#[derive(Debug, Deserialize)]
struct Response<T> {
    result: T,
}