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
        use data_encoding::HEXLOWER_PERMISSIVE;
        let result = HEXLOWER_PERMISSIVE.decode(password_hash.as_bytes())?;
        if result.len() != 32 {
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
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_into() {
        let banned_hash: PasswordHash =
            "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b85"
                .parse()
                .unwrap();
        let not_banned_hash: PasswordHash =
            "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
                .parse()
                .unwrap();

        assert_eq!(
            banned_hash.digest,
            "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b85"
        );
        assert_eq!(
            banned_hash.digest_bytes,
            [
                65, 154, 99, 108, 204, 42, 165, 92, 115, 71, 199, 153, 113, 167, 56, 195, 16, 59,
                52, 37, 75, 215, 156, 26, 61, 118, 125, 246, 42, 120, 139, 133
            ]
        );

        assert_eq!(
            not_banned_hash.digest,
            "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
        );
        assert_eq!(
            not_banned_hash.digest_bytes,
            [
                65, 154, 99, 108, 204, 42, 165, 92, 115, 71, 199, 153, 113, 167, 56, 195, 16, 59,
                52, 37, 75, 215, 156, 26, 61, 118, 125, 246, 42, 120, 139, 134
            ]
        );
    }

    #[test]
    fn test_validity() {
        use r2d2_redis::redis;

        let banned_hash: PasswordHash =
            "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b85"
                .parse()
                .unwrap();
        let not_banned_hash: PasswordHash =
            "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
                .parse()
                .unwrap();

        let client = redis::Client::open("redis://127.0.0.1/").unwrap();
        let redis_conn = client.get_connection().unwrap();
        assert_eq!(redis_conn.is_open(), true);

        assert_eq!(banned_hash.check_validity(&redis_conn).is_err(), true);
        assert_eq!(not_banned_hash.check_validity(&redis_conn).is_ok(), true);
    }
}
