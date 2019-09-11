use crate::config;

use futures::future::Future;
use instrumented::instrument;

#[derive(Debug)]
pub struct MessageError(pub String);

impl From<reqwest::Error> for MessageError {
    fn from(err: reqwest::Error) -> Self {
        Self(err.to_string())
    }
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResponse {
    pub id: String,
    pub href: String,
    pub direction: String,
    pub r#type: String,
    pub originator: String,
    pub body: String,
    pub gateway: i64,
    pub datacoding: String,
    pub mclass: i64,
    pub created_datetime: String,
    pub recipients: Recipients,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Recipients {
    pub total_count: i64,
    pub total_sent_count: i64,
    pub total_delivered_count: i64,
    pub total_delivery_failed_count: i64,
    pub items: Vec<Item>,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub recipient: i64,
    pub status: String,
    pub status_datetime: String,
    pub message_part_count: i64,
}

pub struct Client {
    client: reqwest::async::Client,
}

impl Client {
    pub fn new() -> Self {
        use reqwest::header;
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!(
                "AccessKey {}",
                config::CONFIG.messagebird.api_key
            ))
            .unwrap(),
        );

        Self {
            client: reqwest::async::Client::builder()
                .default_headers(headers)
                .build()
                .expect("couldn't create reqwest client for messagebird"),
        }
    }

    pub fn send_sms_async(
        &self,
        recipient: &str,
        originator: &str,
        body: &str,
    ) -> impl Future<Item = reqwest::async::Response, Error = reqwest::Error> {
        let form = reqwest::async::multipart::Form::new()
            .text("recipients", recipient.to_owned())
            .text("originator", originator.to_owned())
            .text("body", body.to_owned());
        self.client
            .post("https://rest.messagebird.com/messages")
            .multipart(form)
            .send()
    }

    #[instrument(INFO)]
    pub fn send_sms(
        &self,
        country: &str,
        recipient: &str,
        body: &str,
    ) -> Result<SendMessageResponse, MessageError> {
        info!("sending sms recipient={} body='{}'", recipient, body);

        use futures::Future;
        use tokio::executor::Executor;

        let mut exec = tokio::executor::DefaultExecutor::current();

        let originator = match config::CONFIG.messagebird.originators.get(country) {
            Some(originator) => originator,
            _ => config::CONFIG.messagebird.originators.get("US").unwrap(),
        };

        let (tx, rx) = futures::sync::oneshot::channel();
        exec.spawn(Box::new(
            self.send_sms_async(recipient, originator, body)
                .and_then(|mut resp| resp.text())
                .and_then(|resp| {
                    info!("response: {}", resp);
                    let r: SendMessageResponse = serde_json::from_str(&resp).unwrap();
                    futures::future::ok(r)
                })
                .then(move |r| tx.send(r).map_err(|_werr| error!("failure"))),
        ))
        .unwrap();
        rx.wait().unwrap().map_err(MessageError::from)
    }
}
