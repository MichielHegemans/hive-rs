use reqwest::{Client, Response as ReqRes, Error};
use serde::{Serialize, Deserialize};
use serde::de::{DeserializeOwned};
use async_recursion::async_recursion;

pub struct HiveClient {
    hosts: Vec<String>,
    current_host: usize,
    client: Client,
    max_retry: u8,
}

impl HiveClient {

    pub fn new(hosts: Vec<String>, max_retry: Option<u8>) -> HiveClient {
        assert!(hosts.len() > 0, "At least one host must be specified.");
        let client = Client::new();
        Self { hosts, client, current_host: 0 , max_retry: max_retry.unwrap_or(3)}
    }

    pub async fn post<T>(&mut self, method: String, params: Option<Vec<u32>>) -> Result<T, Error>
        where T: DeserializeOwned, {
        let params_vec = params.unwrap_or(vec![]);
        let payload = Request::new(method, params_vec).to_string();
        self.post_(payload, 1).await
    }

    #[async_recursion]
    async fn post_<T>(&mut self, payload: String, retries: u8) -> Result<T, Error>
        where T: DeserializeOwned, {
        let on_err_copy = payload.clone();
        let response = self.client.post(self.get_host_())
            .body(payload)
            .send()
            .await;
        match response {
            Ok(res) => self.handle_ok_(on_err_copy, res, retries).await,
            Err(err) => self.handle_error_(on_err_copy, err, retries).await,
        }
    }

    #[async_recursion]
    async fn handle_ok_<T>(&mut self, payload: String, res: ReqRes, retries: u8) -> Result<T, Error>
        where T: DeserializeOwned, {
        let status = res.status();
        return if status.is_success() {
            let body = res.text().await.unwrap();
            let output: Response<T> = serde_json::from_str(&body).unwrap();
            Ok(output.result)
        } else if status.is_server_error() && self.can_retry_(retries) {
            self.retry_(payload, retries).await
        } else {
            Err(res.error_for_status().err().unwrap())
        }
    }

    #[async_recursion]
    async fn handle_error_<T>(&mut self, payload: String, err: Error, retries: u8) -> Result<T, Error>
        where T: DeserializeOwned, {
        let has_failed = err.status().unwrap().is_server_error() && self.can_retry_(retries);
        match has_failed {
            true => {
                self.retry_(payload, retries).await
            },
            false => Err(err)
        }
    }

    async fn retry_<T>(&mut self, payload: String, retries: u8) -> Result<T, Error>
        where T: DeserializeOwned, {
        self.current_host = (self.current_host + 1) % self.hosts.len();
        self.post_(payload, retries + 1).await
    }

    fn get_host_(&self) -> &String {
        self.hosts.get(self.current_host).unwrap()
    }

    fn can_retry_(&self, retries: u8) -> bool {
        retries < self.max_retry
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

#[cfg(test)]
mod hive_client_test {
    use httpmock::Method::POST;
    use httpmock::MockServer;
    use reqwest::{Error, StatusCode};
    use crate::client::hive_client::HiveClient;

    const MAX_RETRY: Option<u8> = Some(2);
    const SUCCESS: &str = "{ \"result\": \"success\" }";
    const FAIL: &str = "{ \"result\": \"fail\" }";

    #[tokio::test]
    async fn client_retry() {
        let server_a = MockServer::start();
        let server_b = MockServer::start();
        let servers = vec![server_a.base_url(), server_b.base_url()];
        let fail_mock = server_a.mock(|when, then| {
            when.method(POST);
            then.status(500)
                .body(FAIL.to_string());
        });

        let success_mock = server_b.mock(|when, then| {
            when.method(POST);
            then.status(200)
                .body(SUCCESS.to_string());
        });

        let mut client = HiveClient::new(servers, MAX_RETRY);
        let result: Result<String, Error> = client.post("cool.method".to_string(), None).await;
        fail_mock.assert();
        success_mock.assert();
        match result {
            Ok(res) => assert_eq!(res, "success"),
            Err(_) => assert!(false),
        }
    }

    #[tokio::test]
    async fn client_retry_max() {
        let server_a = MockServer::start();
        let servers = vec![server_a.base_url()];
        let fail_mock = server_a.mock(|when, then| {
            when.method(POST);
            then.status(500)
                .body(FAIL);
        });
        let mut client = HiveClient::new(servers, MAX_RETRY);
        let result: Result<String, Error> = client.post("cool.method".to_string(), None).await;
        fail_mock.assert_hits(usize::from(MAX_RETRY.unwrap()));
        assert_eq!(result.err().unwrap().status().unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
