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
}

/// Represents a valid email address.
#[derive(Debug, Clone)]
pub struct Email {
    email_as_entered: String,
    email_without_labels: String,
    inbox: String,
    user: String,
    label: String,
    domain: String,
}

impl FromStr for Email {
    type Err = EmailError;

    fn from_str(email: &str) -> Result<Self, Self::Err> {
        if let Some(caps) = EMAIL_RE.captures(email) {
            let inbox = &caps["inbox"];
            let domain = &caps["domain"];
            let (user, label) = if let Some(label_idx) = inbox.find('+') {
                (&inbox[0..label_idx], &inbox[(label_idx + 1)..])
            } else {
                (inbox, "")
            };

            Ok(Email {
                email_as_entered: email.into(),
                email_without_labels: format!("{}@{}", user, domain),
                inbox: inbox.into(),
                user: user.into(),
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
    fn is_valid(&self) -> Result<(), EmailError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_regex() {
        let cap1 = EMAIL_RE.captures("brenden@brndn.io").unwrap();

        println!("{:?}", cap1);
        assert_eq!("brenden", &cap1["inbox"]);
        assert_eq!("brndn.io", &cap1["domain"]);

        let cap2 = EMAIL_RE.captures("brenden+lol@brndn.io").unwrap();

        println!("{:?}", cap2);
        assert_eq!("brenden+lol", &cap2["inbox"]);
        assert_eq!("brndn.io", &cap2["domain"]);
    }

    #[test]
    fn test_into_normal() {
        let addr = "brenden@brndn.io";
        let email: Email = addr.parse().unwrap();

        assert_eq!(email.domain, "brndn.io");
        assert_eq!(email.inbox, "brenden");
        assert_eq!(email.user, "brenden");
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
        assert_eq!(email.user, "brenden");
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
        assert_eq!(email.user, "brenden");
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
        assert_eq!(email.user, "brenden");
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
}
