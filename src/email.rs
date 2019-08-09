use instrumented::instrument;
use regex::Regex;
use std::str::FromStr;

lazy_static! {
    // Based on the HTML5 spec: https://www.w3.org/TR/html5/forms.html#valid-e-mail-address
    static ref EMAIL_RE: Regex = Regex::new(r####"^(?P<inbox>[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+)@(?P<domain>[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)$"####).unwrap();
}

#[derive(Debug, Fail)]
pub enum EmailError {
    #[fail(display = "invalid email address (bad format): {}", email)]
    BadFormat { email: String },
    #[fail(display = "invalid email domain (banned domain): {}", email)]
    BannedDomain { email: String },
    #[fail(
        display = "invalid email domain suffix (not in public suffix list): {}",
        email
    )]
    InvalidSuffix { email: String },
    #[fail(display = "database error: {}", err)]
    DatabaseError { err: String },
    #[fail(display = "invalid domain (DNS error): {}", email)]
    InvalidDomain { email: String },
    #[fail(display = "DNS resolution error: {}", err)]
    DNSFailure { err: String },
}

/// Represents a valid email address.
#[derive(Debug, Clone)]
pub struct Email {
    pub email_as_entered: String,
    pub email_without_labels: String,
    inbox: String,
    client: String,
    label: String,
    domain: String,
}

impl From<r2d2_redis_cluster::redis_cluster_rs::redis::RedisError> for EmailError {
    fn from(err: r2d2_redis_cluster::redis_cluster_rs::redis::RedisError) -> EmailError {
        EmailError::DatabaseError {
            err: format!("{}", err),
        }
    }
}

impl From<std::net::AddrParseError> for EmailError {
    fn from(err: std::net::AddrParseError) -> EmailError {
        EmailError::DNSFailure {
            err: format!("{}", err),
        }
    }
}

impl From<trust_dns::error::ClientError> for EmailError {
    fn from(err: trust_dns::error::ClientError) -> EmailError {
        EmailError::DNSFailure {
            err: format!("{}", err),
        }
    }
}

impl FromStr for Email {
    type Err = EmailError;

    fn from_str(email: &str) -> Result<Self, Self::Err> {
        if let Some(caps) = EMAIL_RE.captures(email) {
            let inbox = &caps["inbox"];
            let domain = &caps["domain"];
            // Strip any values after the first `+`
            let (client, label) = if let Some(label_idx) = inbox.find('+') {
                (&inbox[0..label_idx], &inbox[(label_idx + 1)..])
            } else {
                (inbox, "")
            };
            // Remove all `.` occurrences
            let client = client.replace(".", "");

            Ok(Email {
                email_as_entered: email.into(),
                email_without_labels: format!("{}@{}", client, domain),
                inbox: inbox.into(),
                client,
                label: label.into(),
                domain: domain.into(),
            })
        } else {
            Err(EmailError::BadFormat {
                email: email.into(),
            })
        }
    }
}

impl Email {
    #[instrument(INFO)]
    pub fn check_validity(
        &self,
        redis_conn: &mut r2d2_redis_cluster::redis_cluster_rs::Connection,
    ) -> Result<(), EmailError> {
        use futures::Future;
        use r2d2_redis_cluster::redis_cluster_rs::Commands;
        use std::str::FromStr;
        use tokio::executor::Executor;
        use trust_dns::client::{ClientFuture, ClientHandle};
        use trust_dns::rr::{DNSClass, Name, RecordType};
        use trust_dns::udp::UdpClientStream;

        let is_banned_email_domain: bool =
            redis_conn.sismember("banned_email_domains", &self.domain)?;
        let in_public_suffix_list: bool =
            redis_conn.sismember("public_suffix_list", &self.domain)?;
        if is_banned_email_domain {
            return Err(EmailError::BannedDomain {
                email: self.email_as_entered.clone(),
            });
        } else if in_public_suffix_list {
            return Err(EmailError::InvalidSuffix {
                email: self.email_as_entered.clone(),
            });
        }

        // Check domain is resolvable
        let mut exec = tokio::executor::DefaultExecutor::current();

        let stream = UdpClientStream::with_timeout(
            ([8, 8, 8, 8], 53).into(),
            std::time::Duration::from_secs(1),
        );
        let (bg, mut client) = ClientFuture::connect(stream);
        exec.spawn(Box::new(bg)).unwrap();

        // Specify the name, note the final '.' which specifies it's an FQDN
        let name = Name::from_str(&format!("{}.", &self.domain)).unwrap();

        // NOTE: see 'Setup a connection' example above
        // Send the query and get a message response, see RecordType for all supported options
        let query = client.query(name, DNSClass::IN, RecordType::MX);

        let (tx, rx) = futures::sync::oneshot::channel();
        exec.spawn(Box::new(query.then(move |r| {
            tx.send(r)
                .map_err(|err| error!("DNS query error: {:?}", err))
        })))
        .unwrap();
        let response = rx.wait().unwrap().unwrap();

        let answers = response.answers();
        let dns_valid = !answers.is_empty();

        if !dns_valid {
            Err(EmailError::InvalidDomain {
                email: self.email_as_entered.clone(),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_regex() {
        let cap1 = EMAIL_RE.captures("brenden@brndn.io").unwrap();

        assert_eq!("brenden", &cap1["inbox"]);
        assert_eq!("brndn.io", &cap1["domain"]);

        let cap2 = EMAIL_RE.captures("brenden+lol@brndn.io").unwrap();

        assert_eq!("brenden+lol", &cap2["inbox"]);
        assert_eq!("brndn.io", &cap2["domain"]);
    }

    #[test]
    fn test_into_normal() {
        let addr = "brenden@brndn.io";
        let email: Email = addr.parse().unwrap();

        assert_eq!(email.domain, "brndn.io");
        assert_eq!(email.inbox, "brenden");
        assert_eq!(email.client, "brenden");
        assert_eq!(email.label, "");
        assert_eq!(email.email_as_entered, addr);
        assert_eq!(email.email_without_labels, addr);
    }

    #[test]
    fn test_into_with_label() {
        let addr = "brenden+hi@brndn.io";
        let email: Email = addr.parse().unwrap();

        assert_eq!(email.domain, "brndn.io");
        assert_eq!(email.inbox, "brenden+hi");
        assert_eq!(email.client, "brenden");
        assert_eq!(email.label, "hi");
        assert_eq!(email.email_as_entered, addr);
        assert_eq!(email.email_without_labels, "brenden@brndn.io");
    }

    #[test]
    fn test_into_with_dots() {
        let addr = "b.r.e.n.d.e.n+hi@brndn.io";
        let email: Email = addr.parse().unwrap();

        assert_eq!(email.domain, "brndn.io");
        assert_eq!(email.inbox, "b.r.e.n.d.e.n+hi");
        assert_eq!(email.client, "brenden");
        assert_eq!(email.label, "hi");
        assert_eq!(email.email_as_entered, addr);
        assert_eq!(email.email_without_labels, "brenden@brndn.io");
    }

    #[test]
    fn test_into_with_multiple_labels() {
        let addr = "brenden+hi+lol@brndn.io";
        let email: Email = addr.parse().unwrap();

        assert_eq!(email.domain, "brndn.io");
        assert_eq!(email.inbox, "brenden+hi+lol");
        assert_eq!(email.client, "brenden");
        assert_eq!(email.label, "hi+lol");
        assert_eq!(email.email_as_entered, addr);
        assert_eq!(email.email_without_labels, "brenden@brndn.io");
    }

    #[test]
    fn test_into_with_missing_label() {
        let addr = "brenden+@brndn.io";
        let email: Email = addr.parse().unwrap();

        assert_eq!(email.domain, "brndn.io");
        assert_eq!(email.inbox, "brenden+");
        assert_eq!(email.client, "brenden");
        assert_eq!(email.label, "");
        assert_eq!(email.email_as_entered, addr);
        assert_eq!(email.email_without_labels, "brenden@brndn.io");
    }

    #[test]
    fn test_into_invalid() {
        let addr = "brendenbrndnio";
        let result: Result<Email, EmailError> = addr.parse();

        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn test_validation() {
        use futures::future;

        tokio::run(future::lazy(|| {
            let client = redis::Client::open("redis://127.0.0.1/").unwrap();
            let mut redis_conn = client.get_connection().unwrap();
            assert_eq!(redis_conn.is_open(), true);

            assert_eq!(
                Email::from_str("brenden@brndn.io")
                    .unwrap()
                    .check_validity(&mut redis_conn)
                    .is_ok(),
                true
            );

            assert_eq!(
                Email::from_str("brenden@com")
                    .unwrap()
                    .check_validity(&mut redis_conn)
                    .is_err(),
                true
            );

            assert_eq!(
                Email::from_str("brenden@mailinator.com")
                    .unwrap()
                    .check_validity(&mut redis_conn)
                    .is_err(),
                true
            );

            assert_eq!(
                Email::from_str("brenden@lolnotactuallyarealdomainthatexists.com")
                    .unwrap()
                    .check_validity(&mut redis_conn)
                    .is_err(),
                true
            );
            future::ok(())
        }));
    }
}
