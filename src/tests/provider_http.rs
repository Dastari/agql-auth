//! Header-recording in-memory HTTP client for provider tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value as JsonValue, json};

use crate::prelude::*;

/// One recorded provider request.
#[derive(Debug, Clone)]
pub(super) struct RecordedRequest {
    pub(super) method: &'static str,
    pub(super) url: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) form: Vec<(String, String)>,
}

impl RecordedRequest {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub(super) fn form_value(&self, name: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Canned responses: `Ok(json)` or `Err(())` for a transport/status failure
/// such as HTTP 401.
#[derive(Clone)]
pub(super) struct RecordingHttpClient {
    supports_headers: bool,
    get_responses: Arc<Mutex<HashMap<String, Result<JsonValue, ()>>>>,
    post_responses: Arc<Mutex<Vec<Result<JsonValue, ()>>>>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl RecordingHttpClient {
    pub(super) fn new(supports_headers: bool) -> Self {
        Self {
            supports_headers,
            get_responses: Arc::new(Mutex::new(HashMap::new())),
            post_responses: Arc::new(Mutex::new(Vec::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(super) fn set_get(&self, url: &str, response: Result<JsonValue, ()>) {
        self.get_responses
            .lock()
            .unwrap()
            .insert(url.to_string(), response);
    }

    /// Sets the response for every subsequent POST.
    pub(super) fn set_post(&self, response: Result<JsonValue, ()>) {
        *self.post_responses.lock().unwrap() = vec![response];
    }

    pub(super) fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub(super) fn posts(&self) -> Vec<RecordedRequest> {
        self.requests()
            .into_iter()
            .filter(|request| request.method == "POST")
            .collect()
    }

    pub(super) fn gets_to(&self, url: &str) -> Vec<RecordedRequest> {
        self.requests()
            .into_iter()
            .filter(|request| request.method == "GET" && request.url == url)
            .collect()
    }

    fn get(&self, url: &str, headers: &[(String, String)]) -> crate::AuthResult<JsonValue> {
        self.requests.lock().unwrap().push(RecordedRequest {
            method: "GET",
            url: url.to_string(),
            headers: headers.to_vec(),
            form: Vec::new(),
        });
        match self.get_responses.lock().unwrap().get(url) {
            Some(Ok(value)) => Ok(value.clone()),
            _ => Err(AuthError::Store("mock GET failed".to_string())),
        }
    }

    fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        form: &[(String, String)],
    ) -> crate::AuthResult<JsonValue> {
        self.requests.lock().unwrap().push(RecordedRequest {
            method: "POST",
            url: url.to_string(),
            headers: headers.to_vec(),
            form: form.to_vec(),
        });
        match self.post_responses.lock().unwrap().first() {
            Some(Ok(value)) => Ok(value.clone()),
            _ => Err(AuthError::Store("mock POST failed".to_string())),
        }
    }
}

#[async_trait]
impl OidcHttpClient for RecordingHttpClient {
    async fn get_json(&self, url: &str) -> crate::AuthResult<JsonValue> {
        self.get(url, &[])
    }

    async fn post_form_json(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> crate::AuthResult<JsonValue> {
        self.post(url, &[], form)
    }

    fn supports_request_headers(&self) -> bool {
        self.supports_headers
    }

    async fn get_json_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> crate::AuthResult<JsonValue> {
        assert!(
            self.supports_headers,
            "header request on header-less client"
        );
        self.get(url, headers)
    }

    async fn post_form_json_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
        form: &[(String, String)],
    ) -> crate::AuthResult<JsonValue> {
        assert!(
            self.supports_headers,
            "header request on header-less client"
        );
        self.post(url, headers, form)
    }
}

pub(super) fn bearer_token_response(access_token: &str) -> JsonValue {
    json!({
        "access_token": access_token,
        "token_type": "bearer",
        "scope": "read:user,user:email"
    })
}
