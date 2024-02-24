use sendgrid::{Mail, SGClient};
use serde::Deserialize;
use shared::common::EmailFrom;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendGridConfig {
    pub api_key: String,
}

pub struct SendGridClient {
    inner: SGClient,
}

impl SendGridClient {
    pub fn new(config: SendGridConfig) -> Self {
        Self {
            inner: SGClient::new(config.api_key),
        }
    }

    pub async fn send(
        &self,
        from: EmailFrom,
        text: String,
        subject: String,
        to: serde_email::Email,
    ) -> anyhow::Result<()> {
        let mail = Mail::new()
            .add_from(from.email.as_str())
            .add_from_name(from.name.as_str())
            .add_html(text.as_str())
            .add_subject(subject.as_str())
            .add_to((to.as_str(), "").into());

        let res = self.inner.send(mail).await?;

        tracing::debug!(
            "Email (subject: {subject} to: {to}) from `{from:?}` has been sent. Response: {res:?}"
        );

        Ok(())
    }
}
