use diesel::prelude::*;
use diesel::sql_types::{Integer, Text};
use email;
use futures::future;
use instrumented::{instrument, prometheus, register};
use rolodex_grpc::proto::{
    auth_response, new_user_response, server, AuthRequest, AuthResponse, NewUserRequest,
    NewUserResponse,
};
use rolodex_grpc::tower_grpc::{Request, Response};

lazy_static! {
    static ref USER_ADDED: prometheus::IntCounter = {
        let counter = prometheus::IntCounter::new("new_user_added", "New user added").unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
    static ref USER_AUTHED: prometheus::IntCounter = {
        let counter =
            prometheus::IntCounter::new("user_authed", "User authenticated successfully").unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
}

#[derive(Clone)]
pub struct Rolodex {
    db_reader: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
    db_writer: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
    redis_reader: r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
    redis_writer: r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
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
    #[fail(display = "invalid user_id: {}", err)]
    InvalidUserId { err: String },
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

impl From<uuid::parser::ParseError> for RequestError {
    fn from(err: uuid::parser::ParseError) -> RequestError {
        RequestError::InvalidUserId {
            err: format!("{}", err),
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
            RequestError::InvalidUserId { .. } => rolodex_grpc::proto::Error::InvalidUserId as i32,
        }
    }
}

sql_function! {
    fn crypt(value: Text, salt: Text) -> Text;
}

sql_function! {
    fn gen_salt(alg: Text, bits: Integer) -> Text;
}

impl Rolodex {
    pub fn new(
        db_reader: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        db_writer: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        redis_reader: r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
        redis_writer: r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
    ) -> Self {
        Rolodex {
            db_reader,
            db_writer,
            redis_reader,
            redis_writer,
        }
    }

    /// Returns the user_id for this user if auth succeeds
    #[instrument(INFO)]
    fn handle_authenticate(&self, request: &AuthRequest) -> Result<String, RequestError> {
        use crate::schema::users;
        use diesel::prelude::*;

        let request_uuid = uuid::Uuid::parse_str(&request.user_id)?;

        let conn = self.db_reader.get().unwrap();

        let uuid: uuid::Uuid = users::table
            .select(users::uuid)
            .filter(
                users::dsl::password_hash
                    .eq(crypt(
                        request.password_hash.clone(),
                        users::dsl::password_hash,
                    ))
                    .and(users::dsl::uuid.eq(&request_uuid)),
            )
            .first(&conn)?;

        USER_AUTHED.inc();
        Ok(uuid.to_simple().to_string())
    }

    /// Returns the user_id for this user if account creation succeeded
    #[instrument(INFO)]
    fn handle_add_user(&self, request: &NewUserRequest) -> Result<String, RequestError> {
        use crate::models::{NewUniqueEmailAddress, User};
        use crate::schema::{unique_email_addresses, users};
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

        let email: Email = request.email.to_lowercase().parse()?;
        let redis_conn = self.redis_reader.get()?;
        email.check_validity(&*redis_conn)?;

        let email_as_entered = email.email_as_entered.clone();
        let email_without_labels = email.email_without_labels.clone();

        let conn = self.db_writer.get().unwrap();
        let user = conn.transaction::<_, Error, _>(|| {
            let user: User = diesel::insert_into(users::table)
                .values(&vec![(
                    users::dsl::full_name.eq(request.full_name.clone()),
                    users::dsl::password_hash
                        .eq(crypt(request.password_hash.clone(), gen_salt("bf", 8))),
                    users::dsl::phone_number.eq(number
                        .format()
                        .mode(phonenumber::Mode::International)
                        .to_string()),
                )])
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

        USER_ADDED.inc();
        Ok(user.uuid.to_simple().to_string())
    }
}

impl server::Rolodex for Rolodex {
    type AuthenticateFuture =
        future::FutureResult<Response<AuthResponse>, rolodex_grpc::tower_grpc::Status>;
    type AddUserFuture =
        future::FutureResult<Response<NewUserResponse>, rolodex_grpc::tower_grpc::Status>;

    fn authenticate(&mut self, request: Request<AuthRequest>) -> Self::AuthenticateFuture {
        let response = match self
            .handle_authenticate(request.get_ref())
            .map(|res| AuthResponse {
                result: Some(auth_response::Result::UserId(res)),
            })
            .map_err(|err| AuthResponse {
                result: Some(auth_response::Result::Error(err.into())),
            }) {
            Ok(res) => Response::new(res),
            Err(res) => Response::new(res),
        };

        future::ok(response)
    }

    fn add_user(&mut self, request: Request<NewUserRequest>) -> Self::AddUserFuture {
        let response = match self
            .handle_add_user(request.get_ref())
            .map(|res| NewUserResponse {
                result: Some(new_user_response::Result::UserId(res)),
            })
            .map_err(|err| NewUserResponse {
                result: Some(new_user_response::Result::Error(err.into())),
            }) {
            Ok(res) => Response::new(res),
            Err(res) => Response::new(res),
        };

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

        macro_rules! empty_tables {
                ( $( $x:ident ),* ) => {
                $(
                    diesel::delete($x::table).execute(&conn).unwrap();
                    assert_eq!(Ok(0), $x::table.select(count($x::id)).first(&conn));
                )*
            };
        }

        empty_tables![unique_email_addresses, users];
    }

    fn email_in_table(
        db_pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        email: &str,
    ) -> bool {
        use crate::schema::unique_email_addresses;
        use diesel::dsl::*;
        use diesel::prelude::*;

        let conn = db_pool.get().unwrap();

        let count: i64 = unique_email_addresses::table
            .select(count(unique_email_addresses::id))
            .filter(unique_email_addresses::email_as_entered.eq(email))
            .first(&conn)
            .unwrap();
        count > 0
    }

    #[test]
    fn test_add_user_valid() {
        let _lock = LOCK.lock().unwrap();

        let (db_pool, redis_pool) = get_pools();
        empty_tables(&db_pool);

        let rolodex = Rolodex::new(
            db_pool.clone(),
            db_pool.clone(),
            redis_pool.clone(),
            redis_pool.clone(),
        );

        let pw_hash = "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86";

        let result = rolodex.handle_add_user(&NewUserRequest {
            full_name: "Bob Marley".into(),
            email: "bob@aol.com".into(),
            phone_number: Some(PhoneNumber {
                country: "US".into(),
                number: "4013213952".into(),
            }),
            password_hash: pw_hash.into(),
        });
        assert_eq!(result.is_ok(), true);
        assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

        let user_id = result.unwrap();

        let auth_result = rolodex.handle_authenticate(&AuthRequest {
            user_id: user_id.to_string(),
            password_hash: pw_hash.into(),
        });
        assert_eq!(auth_result.is_ok(), true);
        assert_eq!(auth_result.unwrap(), user_id);
    }

    #[test]
    fn test_user_invalid_auth() {
        let _lock = LOCK.lock().unwrap();

        let (db_pool, redis_pool) = get_pools();
        empty_tables(&db_pool);

        let rolodex = Rolodex::new(
            db_pool.clone(),
            db_pool.clone(),
            redis_pool.clone(),
            redis_pool.clone(),
        );

        let user_id = "e9f272e503ff4b73891e77c766e8a251";
        let pw_hash = "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86";

        let auth_result = rolodex.handle_authenticate(&AuthRequest {
            user_id: user_id.to_string(),
            password_hash: pw_hash.into(),
        });
        assert_eq!(auth_result.is_err(), true);
    }

    #[test]
    fn test_add_user_duplicate_email() {
        let _lock = LOCK.lock().unwrap();

        let (db_pool, redis_pool) = get_pools();
        empty_tables(&db_pool);

        let rolodex = Rolodex::new(
            db_pool.clone(),
            db_pool.clone(),
            redis_pool.clone(),
            redis_pool.clone(),
        );

        let pw_hash = "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86";

        let result = rolodex.handle_add_user(&NewUserRequest {
            full_name: "Bob Marley".into(),
            email: "bob@aol.com".into(),
            phone_number: Some(PhoneNumber {
                country: "US".into(),
                number: "4013213953".into(),
            }),
            password_hash: pw_hash.into(),
        });
        assert_eq!(result.is_ok(), true);
        assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

        let user_id = result.unwrap();

        let auth_result = rolodex.handle_authenticate(&AuthRequest {
            user_id: user_id.to_string(),
            password_hash: pw_hash.into(),
        });
        assert_eq!(auth_result.is_ok(), true);
        assert_eq!(auth_result.unwrap(), user_id);

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

        let rolodex = Rolodex::new(
            db_pool.clone(),
            db_pool.clone(),
            redis_pool.clone(),
            redis_pool.clone(),
        );

        let pw_hash = "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86";

        let result = rolodex.handle_add_user(&NewUserRequest {
            full_name: "Bob Marley".into(),
            email: "bob@aol.com".into(),
            phone_number: Some(PhoneNumber {
                country: "US".into(),
                number: "4013213953".into(),
            }),
            password_hash: pw_hash.into(),
        });
        assert_eq!(result.is_ok(), true);
        assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

        let user_id = result.unwrap();

        let auth_result = rolodex.handle_authenticate(&AuthRequest {
            user_id: user_id.to_string(),
            password_hash: pw_hash.into(),
        });
        assert_eq!(auth_result.is_ok(), true);
        assert_eq!(auth_result.unwrap(), user_id);

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
        assert_eq!(email_in_table(&db_pool, "bob2@aol.com"), false);
    }
}
