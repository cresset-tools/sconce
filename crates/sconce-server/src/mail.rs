//! Outbound email for the admin UI (currently just password-reset links).
//!
//! Two backends, chosen from the environment by [`Mailer::from_env`]:
//! - **SMTP** when `SCONCE_SMTP_URL` is set (e.g.
//!   `smtps://user:pass@smtp.example.com:465`) — real delivery via lettre over a
//!   rustls TLS connection (bundled webpki roots, no system CA config).
//! - **dev / stderr** otherwise — the message (including the link) is printed to
//!   the server's stderr, so the flow works end-to-end in development without any
//!   mail server. The `From` address comes from `SCONCE_MAIL_FROM`.

use lettre::message::Mailbox;
use lettre::transport::smtp::Error as SmtpError;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// The default `From` when `SCONCE_MAIL_FROM` is unset.
const DEFAULT_FROM: &str = "Bougie Repo <noreply@bougie.local>";

/// Sends transactional email. Cloneable + `Send`/`Sync` so it can live in the
/// shared UI state.
#[derive(Clone)]
pub enum Mailer {
    /// Real SMTP delivery.
    Smtp {
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
    },
    /// Development backend: print the message to stderr instead of sending.
    Stderr { from: Mailbox },
}

impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the transport (it holds SMTP credentials).
        match self {
            Mailer::Smtp { from, .. } => {
                f.debug_struct("Mailer::Smtp").field("from", from).finish()
            }
            Mailer::Stderr { from } => f
                .debug_struct("Mailer::Stderr")
                .field("from", from)
                .finish(),
        }
    }
}

/// Why sending failed.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("invalid email address: {0}")]
    Address(#[from] lettre::address::AddressError),
    #[error("building the message")]
    Build(#[from] lettre::error::Error),
    #[error("SMTP delivery failed")]
    Smtp(#[from] SmtpError),
}

impl Mailer {
    /// Build a mailer from the environment. Falls back to the stderr backend when
    /// `SCONCE_SMTP_URL` is absent, blank, or unparseable (a warning is logged for
    /// the unparseable case so a typo'd relay URL is visible).
    ///
    /// # Panics
    /// Only if `DEFAULT_FROM` — a compile-time constant — is not a valid mailbox,
    /// which it always is; the `expect` is unreachable in practice.
    #[must_use]
    pub fn from_env() -> Self {
        let from = std::env::var("SCONCE_MAIL_FROM")
            .ok()
            .and_then(|v| v.parse::<Mailbox>().ok())
            .unwrap_or_else(|| {
                DEFAULT_FROM
                    .parse()
                    .expect("DEFAULT_FROM is a valid mailbox")
            });

        match std::env::var("SCONCE_SMTP_URL") {
            Ok(url) if !url.trim().is_empty() => {
                match AsyncSmtpTransport::<Tokio1Executor>::from_url(url.trim()) {
                    Ok(builder) => Mailer::Smtp {
                        transport: builder.build(),
                        from,
                    },
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "SCONCE_SMTP_URL is set but unparseable; falling back to stderr delivery"
                        );
                        Mailer::Stderr { from }
                    }
                }
            }
            _ => Mailer::Stderr { from },
        }
    }

    /// Whether this mailer actually delivers over the network (vs. the dev
    /// stderr backend) — lets the UI tailor its confirmation copy.
    #[must_use]
    pub fn delivers(&self) -> bool {
        matches!(self, Mailer::Smtp { .. })
    }

    /// Send a plain-text message to `to`. For the stderr backend this prints the
    /// message and returns `Ok` (delivery is "to the console").
    pub async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), MailError> {
        let (from, to_box) = match self {
            Mailer::Smtp { from, .. } | Mailer::Stderr { from } => (from.clone(), to.parse()?),
        };
        let message = Message::builder()
            .from(from)
            .to(to_box)
            .subject(subject)
            .body(body.to_owned())?;

        match self {
            Mailer::Smtp { transport, .. } => {
                transport.send(message).await?;
                Ok(())
            }
            Mailer::Stderr { .. } => {
                eprintln!(
                    "\n--- DEV EMAIL (no SMTP configured) -------------------------\n\
                     To: {to}\nSubject: {subject}\n\n{body}\n\
                     ------------------------------------------------------------\n"
                );
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_from_constant_is_a_valid_mailbox() {
        // `from_env` relies on this never failing (its `expect`).
        let from: Mailbox = DEFAULT_FROM.parse().unwrap();
        assert_eq!(from.email.to_string(), "noreply@bougie.local");
    }

    #[tokio::test]
    async fn stderr_backend_accepts_a_valid_recipient() {
        let m = Mailer::Stderr {
            from: DEFAULT_FROM.parse().unwrap(),
        };
        // A well-formed address "sends" (prints) without error...
        assert!(m.send("dev@example.com", "Subject", "body").await.is_ok());
        // ...a malformed one is rejected before any delivery.
        assert!(matches!(
            m.send("not-an-email", "S", "b").await,
            Err(MailError::Address(_))
        ));
    }
}
