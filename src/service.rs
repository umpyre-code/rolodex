use email;
use futures::future;
use instrumented::instrument;
use rolodex_grpc::proto::{
    auth_response, new_user_response, server, AuthRequest, AuthResponse, NewUserRequest,
    NewUserResponse,
};
use tower_grpc::{Request, Response};

#[derive(Clone)]
pub struct Rolodex {
    db_reader: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
    db_writer: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
    redis_pool: r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
}

#[derive(Debug, Fail)]
enum RequestError {
    #[fail(display = "invalid phone number: {}", err)]
    InvalidPhoneNumber { err: String },
    #[fail(display = "invalid email: {}", email)]
    InvalidEmail { email: String },
    #[fail(display = "low quality password: {}", password_hash)]
    LowQualityPassword { password_hash: String },
    #[fail(display = "bad credentials")]
    BadCredentials,
    #[fail(display = "database error: {}", err)]
    DatabaseError { err: String },
    #[fail(display = "email domain DNS failure: {}", err)]
    EmailDNSFailure { err: String },
}

impl From<diesel::result::Error> for RequestError {
    fn from(err: diesel::result::Error) -> RequestError {
        RequestError::DatabaseError {
            err: format!("{}", err),
        }
    }
}

impl From<r2d2_redis::r2d2::Error> for RequestError {
    fn from(err: r2d2_redis::r2d2::Error) -> RequestError {
        RequestError::DatabaseError {
            err: format!("{}", err),
        }
    }
}

impl From<failure::Error> for RequestError {
    fn from(err: failure::Error) -> RequestError {
        RequestError::InvalidPhoneNumber {
            err: format!("{}", err),
        }
    }
}

impl From<email::EmailError> for RequestError {
    fn from(err: email::EmailError) -> RequestError {
        match err {
            email::EmailError::BadFormat { email } => RequestError::InvalidEmail { email },
            email::EmailError::BannedDomain { email } => RequestError::InvalidEmail { email },
            email::EmailError::InvalidSuffix { email } => RequestError::InvalidEmail { email },
            email::EmailError::DatabaseError { err } => RequestError::DatabaseError { err },
            email::EmailError::InvalidDomain { email } => RequestError::InvalidEmail { email },
            email::EmailError::DNSFailure { err } => RequestError::EmailDNSFailure { err },
        }
    }
}

impl From<RequestError> for i32 {
    fn from(err: RequestError) -> Self {
        match err {
            RequestError::InvalidPhoneNumber { .. } => {
                rolodex_grpc::proto::Error::InvalidPhoneNumber as i32
            }
            RequestError::InvalidEmail { .. } => rolodex_grpc::proto::Error::InvalidEmail as i32,
            RequestError::LowQualityPassword { .. } => {
                rolodex_grpc::proto::Error::LowQualityPassword as i32
            }
            RequestError::BadCredentials { .. } => {
                rolodex_grpc::proto::Error::BadCredentials as i32
            }
            RequestError::DatabaseError { .. } => rolodex_grpc::proto::Error::DatabaseError as i32,
            RequestError::EmailDNSFailure { .. } => {
                rolodex_grpc::proto::Error::EmailDnsFailure as i32
            }
        }
    }
}

impl Rolodex {
    pub fn new(
        db_reader: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        db_writer: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        redis_pool: r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
    ) -> Self {
        Rolodex {
            db_reader,
            db_writer,
            redis_pool,
        }
    }

    /// Returns the user_id for this user if auth succeeds
    #[instrument(INFO)]
    fn handle_authenticate(&self, _request: &AuthRequest) -> Result<String, RequestError> {
        Ok("handle_authenticate".to_string())
    }

    /// Returns the user_id for this user if account creation succeeded
    #[instrument(INFO)]
    fn handle_add_user(&self, request: &NewUserRequest) -> Result<String, RequestError> {
        use crate::models::{NewUniqueEmailAddress, NewUser, User};
        use crate::schema::{unique_email_addresses, users};
        use diesel::prelude::*;
        use diesel::result::Error;
        use email::Email;

        let number = if let Some(phone_number) = &request.phone_number {
            let country = phone_number.country.parse().unwrap();
            let number = phonenumber::parse(Some(country), &phone_number.number)?;
            let phonenumber_valid = number.is_valid();
            if !phonenumber_valid {
                return Err(RequestError::InvalidPhoneNumber {
                    err: number.to_string(),
                });
            }
            number
        } else {
            return Err(RequestError::InvalidPhoneNumber {
                err: "no phone number specified".to_string(),
            });
        };

        let new_user = NewUser {
            full_name: request.full_name.clone(),
            password_hash: request.password_hash.clone(),
            phone_number: number
                .format()
                .mode(phonenumber::Mode::International)
                .to_string(),
        };

        let email: Email = request.email.to_lowercase().parse()?;
        let redis_conn = self.redis_pool.get()?;
        email.check_validity(&*redis_conn)?;

        let email_as_entered = email.email_as_entered.clone();
        let email_without_labels = email.email_without_labels.clone();

        let conn = self.db_writer.get().unwrap();
        let user = conn.transaction::<_, Error, _>(|| {
            let user: User = diesel::insert_into(users::table)
                .values(&new_user)
                .get_result(&conn)?;

            let new_unique_email_address = NewUniqueEmailAddress {
                user_id: user.id,
                email_as_entered,
                email_without_labels,
            };

            diesel::insert_into(unique_email_addresses::table)
                .values(&new_unique_email_address)
                .execute(&conn)?;

            Ok(user)
        })?;

        Ok(user.uuid.to_simple().to_string())
    }
}

impl server::Rolodex for Rolodex {
    type AuthenticateFuture = future::FutureResult<Response<AuthResponse>, tower_grpc::Status>;
    type AddUserFuture = future::FutureResult<Response<NewUserResponse>, tower_grpc::Status>;

    fn authenticate(&mut self, request: Request<AuthRequest>) -> Self::AuthenticateFuture {
        let response = Response::new(
            self.handle_authenticate(request.get_ref())
                .map(|res| AuthResponse {
                    result: Some(auth_response::Result::UserId(res)),
                })
                .map_err(|err| AuthResponse {
                    result: Some(auth_response::Result::Error(err.into())),
                })
                .unwrap(),
        );

        future::ok(response)
    }

    fn add_user(&mut self, request: Request<NewUserRequest>) -> Self::AddUserFuture {
        let response = Response::new(
            self.handle_add_user(request.get_ref())
                .map(|res| NewUserResponse {
                    result: Some(new_user_response::Result::UserId(res)),
                })
                .map_err(|err| NewUserResponse {
                    result: Some(new_user_response::Result::Error(err.into())),
                })
                .unwrap(),
        );
        future::ok(response)
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use rolodex_grpc::proto::PhoneNumber;
    use std::sync::Mutex;

    lazy_static! {
        static ref LOCK: Mutex<i32> = Mutex::new(0);
    }

    fn get_pools() -> (
        diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
    ) {
        use diesel::pg::PgConnection;
        use diesel::r2d2::{ConnectionManager, Pool};
        let pg_manager = ConnectionManager::<PgConnection>::new(
            "postgres://postgres:password@127.0.0.1:5432/umpyre",
        );
        let db_pool = Pool::builder().build(pg_manager).unwrap();

        let redis_manager = r2d2_redis::RedisConnectionManager::new("redis://127.0.0.1/").unwrap();
        let redis_pool = r2d2_redis::r2d2::Pool::builder()
            .build(redis_manager)
            .unwrap();

        (db_pool, redis_pool)
    }

    fn empty_tables(
        db_pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
    ) {
        use crate::schema::{unique_email_addresses, users};
        use diesel::dsl::*;
        use diesel::prelude::*;

        let conn = db_pool.get().unwrap();

        diesel::delete(unique_email_addresses::table)
            .execute(&conn)
            .unwrap();
        diesel::delete(users::table).execute(&conn).unwrap();

        macro_rules! empty_tables {
                ( $( $x:ident ),* ) => {
                $(
                    assert_eq!(Ok(0), $x::table.select(count($x::id)).first(&conn));
                )*
            };
        }

        empty_tables![users, unique_email_addresses];

    }

    #[test]
    fn test_add_user_valid() {
        let _lock = LOCK.lock().unwrap();

        let (db_pool, redis_pool) = get_pools();
        empty_tables(&db_pool);

        let rolodex = Rolodex::new(db_pool.clone(), db_pool.clone(), redis_pool);

        let result = rolodex.handle_add_user(&NewUserRequest {
            full_name: "Bob Marley".into(),
            email: "bob@aol.com".into(),
            phone_number: Some(PhoneNumber {
                country: "US".into(),
                number: "4013213952".into(),
            }),
            password_hash: "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
                .into(),
        });
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn test_add_user_duplicate_email() {
        let _lock = LOCK.lock().unwrap();

        let (db_pool, redis_pool) = get_pools();
        empty_tables(&db_pool);

        let rolodex = Rolodex::new(db_pool.clone(), db_pool.clone(), redis_pool);

        let result = rolodex.handle_add_user(&NewUserRequest {
            full_name: "Bob Marley".into(),
            email: "bob@aol.com".into(),
            phone_number: Some(PhoneNumber {
                country: "US".into(),
                number: "4013213953".into(),
            }),
            password_hash: "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
                .into(),
        });
        assert_eq!(result.is_ok(), true);

        let result = rolodex.handle_add_user(&NewUserRequest {
            full_name: "Bob Marley".into(),
            email: "bob@aol.com".into(),
            phone_number: Some(PhoneNumber {
                country: "US".into(),
                number: "4013213954".into(),
            }),
            password_hash: "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
                .into(),
        });
        assert_eq!(result.is_err(), true);
    }

    #[test]
    fn test_add_user_duplicate_phone() {
        let _lock = LOCK.lock().unwrap();

        let (db_pool, redis_pool) = get_pools();
        empty_tables(&db_pool);

        let rolodex = Rolodex::new(db_pool.clone(), db_pool.clone(), redis_pool);

        let result = rolodex.handle_add_user(&NewUserRequest {
            full_name: "Bob Marley".into(),
            email: "bob@aol.com".into(),
            phone_number: Some(PhoneNumber {
                country: "US".into(),
                number: "4013213953".into(),
            }),
            password_hash: "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
                .into(),
        });
        assert_eq!(result.is_ok(), true);

        let result = rolodex.handle_add_user(&NewUserRequest {
            full_name: "Bob Marley".into(),
            email: "bob2@aol.com".into(),
            phone_number: Some(PhoneNumber {
                country: "US".into(),
                number: "4013213953".into(),
            }),
            password_hash: "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
                .into(),
        });
        assert_eq!(result.is_err(), true);
    }
}
