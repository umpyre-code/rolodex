use instrumented::instrument;
use std::str::FromStr;

#[derive(Debug, Fail)]
pub enum PasswordHashError {
    #[fail(display = "invalid password hash (bad format): {}", password_hash)]
    BadFormat { password_hash: String },
    #[fail(display = "invalid password hash (banned): {}", password_hash)]
    BannedPassword { password_hash: String },
    #[fail(display = "database error: {}", err)]
    DatabaseError { err: String },
    #[fail(display = "unable to decode digest: {}", err)]
    DecodingError { err: String },
}

/// Represents a valid password hash.
#[derive(Debug, Clone)]
pub struct PasswordHash {
    pub digest_bytes: Vec<u8>,
    pub digest: String,
}

impl From<r2d2_redis::redis::RedisError> for PasswordHashError {
    fn from(err: r2d2_redis::redis::RedisError) -> PasswordHashError {
        PasswordHashError::DatabaseError {
            err: format!("{}", err),
        }
    }
}

impl From<data_encoding::DecodeError> for PasswordHashError {
    fn from(err: data_encoding::DecodeError) -> PasswordHashError {
        PasswordHashError::DecodingError {
            err: format!("{}", err),
        }
    }
}

impl FromStr for PasswordHash {
    type Err = PasswordHashError;

    fn from_str(password_hash: &str) -> Result<Self, Self::Err> {
        use data_encoding::BASE64_NOPAD;
        let result = BASE64_NOPAD.decode(password_hash.as_bytes())?;
        if result.len() != 64 {
            Err(PasswordHashError::BadFormat {
                password_hash: password_hash.into(),
            })
        } else {
            Ok(PasswordHash {
                digest_bytes: result,
                digest: password_hash.to_string(),
            })
        }
    }
}

impl PasswordHash {
    #[instrument(INFO)]
    pub fn check_validity(
        &self,
        redis_conn: &r2d2_redis::redis::Connection,
    ) -> Result<(), PasswordHashError> {
        use r2d2_redis::redis::Commands;

        let is_banned_password_hash: bool =
            redis_conn.sismember("banned_password_hashes", &self.digest)?;

        if is_banned_password_hash {
            Err(PasswordHashError::BannedPassword {
                password_hash: self.digest.clone(),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into() {
        let banned_hash: PasswordHash = "HyG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA".parse().unwrap();
        let not_banned_hash: PasswordHash =
            "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA"
                .parse()
                .unwrap();

        assert_eq!(
            banned_hash.digest,
            "HyG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA"
        );

        assert_eq!(
            not_banned_hash.digest,
            "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA"
        );
    }

    #[test]
    fn test_validity() {
        use r2d2_redis::redis;

        let banned_hash: PasswordHash =
            "HyG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA"
                .parse()
                .unwrap();
        let not_banned_hash: PasswordHash =
            "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA"
                .parse()
                .unwrap();

        let client = redis::Client::open("redis://127.0.0.1/").unwrap();
        let redis_conn = client.get_connection().unwrap();
        assert_eq!(redis_conn.is_open(), true);

        let res = banned_hash.check_validity(&redis_conn);
        let banned = match res {
            Err(PasswordHashError::BannedPassword { .. }) => true,
            _ => false,
        };
        assert_eq!(banned, true);
        assert_eq!(not_banned_hash.check_validity(&redis_conn).is_ok(), true);
    }
}
