use base64;
use reqwest::{header, Client as HttpClient, RequestBuilder, Response, Url};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

pub struct ClientConfig {
    api_host: String,
    api_username: String,
    api_password: String,
    http_timeout: Duration,
    dial_timeout: Duration,
    tls_timeout: Duration,
}



