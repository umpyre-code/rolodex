use crate::email;
use crate::models::*;
use crate::schema::*;
use diesel::prelude::*;
use diesel::result::Error;
use diesel::sql_types::{Integer, Text};
use email::Email;
use futures::future;
use instrumented::{instrument, prometheus, register};
use rolodex_grpc::proto::*;
use rolodex_grpc::tower_grpc::{Request, Response};

lazy_static! {
    static ref USER_ADDED: prometheus::IntCounter = {
        let counter = prometheus::IntCounter::new("user_added", "New user added").unwrap();
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
    #[fail(display = "database error: {}", err)]
    DatabaseError { err: String },
    #[fail(display = "email domain DNS failure: {}", err)]
    EmailDNSFailure { err: String },
    #[fail(display = "invalid user_id: {}", err)]
    InvalidUserId { err: String },
    #[fail(display = "resource could not be found")]
    NotFound,
}

impl From<diesel::result::Error> for RequestError {
    fn from(err: diesel::result::Error) -> RequestError {
        match err {
            diesel::result::Error::NotFound => RequestError::NotFound,
            _ => RequestError::DatabaseError {
                err: format!("{}", err),
            },
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

impl From<User> for rolodex_grpc::proto::GetUserResponse {
    fn from(user: User) -> rolodex_grpc::proto::GetUserResponse {
        rolodex_grpc::proto::GetUserResponse {
            user_id: user.uuid.to_simple().to_string(),
            full_name: user.full_name,
            public_key: user.public_key,
        }
    }
}

impl From<User> for rolodex_grpc::proto::AuthResponse {
    fn from(user: User) -> rolodex_grpc::proto::AuthResponse {
        rolodex_grpc::proto::AuthResponse {
            user_id: user.uuid.to_simple().to_string(),
        }
    }
}

impl From<User> for rolodex_grpc::proto::NewUserResponse {
    fn from(user: User) -> rolodex_grpc::proto::NewUserResponse {
        rolodex_grpc::proto::NewUserResponse {
            user_id: user.uuid.to_simple().to_string(),
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
    fn handle_authenticate(&self, request: &AuthRequest) -> Result<AuthResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.user_id)?;

        let conn = self.db_reader.get().unwrap();

        let user: User = users::table
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
        Ok(user.into())
    }

    /// Returns the user_id for this user if account creation succeeded
    #[instrument(INFO)]
    fn handle_add_user(&self, request: &NewUserRequest) -> Result<NewUserResponse, RequestError> {
        let number = if let Some(phone_number) = &request.phone_number {
            let country = phone_number.country_code.parse().unwrap();
            let number = phonenumber::parse(Some(country), &phone_number.national_number)?;
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

        let (region, region_subdivision, city) = if let Some(location) = &request.location {
            (
                Some(location.region.clone()),
                Some(location.region_subdivision.clone()),
                Some(location.city.clone()),
            )
        } else {
            (None, None, None)
        };

        let fields = (
            users::dsl::full_name.eq(request.full_name.clone()),
            users::dsl::password_hash.eq(crypt(request.password_hash.clone(), gen_salt("bf", 8))),
            users::dsl::phone_number.eq(number
                .format()
                .mode(phonenumber::Mode::International)
                .to_string()),
            users::dsl::public_key.eq(request.public_key.clone()),
            users::dsl::region.eq(region),
            users::dsl::region_subdivision.eq(region_subdivision),
            users::dsl::city.eq(city),
        );

        let conn = self.db_writer.get().unwrap();
        let user = conn.transaction::<_, Error, _>(|| {
            let user: User = diesel::insert_into(users::table)
                .values(&vec![fields])
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
        Ok(user.into())
    }

    /// Returns the user_id for this user if account creation succeeded
    #[instrument(INFO)]
    fn handle_get_user(&self, request: &GetUserRequest) -> Result<GetUserResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.user_id)?;

        let conn = self.db_reader.get().unwrap();

        let user: User = users::table
            .filter(users::dsl::uuid.eq(&request_uuid))
            .first(&conn)?;

        Ok(user.into())
    }
}

impl server::Rolodex for Rolodex {
    type AuthenticateFuture =
        future::FutureResult<Response<AuthResponse>, rolodex_grpc::tower_grpc::Status>;
    fn authenticate(&mut self, request: Request<AuthRequest>) -> Self::AuthenticateFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_authenticate(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type AddUserFuture =
        future::FutureResult<Response<NewUserResponse>, rolodex_grpc::tower_grpc::Status>;
    fn add_user(&mut self, request: Request<NewUserRequest>) -> Self::AddUserFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_add_user(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type GetUserFuture =
        future::FutureResult<Response<GetUserResponse>, rolodex_grpc::tower_grpc::Status>;
    fn get_user(&mut self, request: Request<GetUserRequest>) -> Self::GetUserFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_get_user(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type CheckFuture =
        future::FutureResult<Response<HealthCheckResponse>, rolodex_grpc::tower_grpc::Status>;
    fn check(&mut self, _request: Request<HealthCheckRequest>) -> Self::CheckFuture {
        future::ok(Response::new(HealthCheckResponse {
            status: health_check_response::ServingStatus::Serving as i32,
        }))
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use diesel::dsl::*;
    use diesel::r2d2::{ConnectionManager, Pool};
    use std::sync::Mutex;

    lazy_static! {
        static ref LOCK: Mutex<i32> = Mutex::new(0);
    }

    fn get_pools() -> (
        diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
    ) {
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

        tokio::run(future::lazy(|| {
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
                    country_code: "US".into(),
                    national_number: "4013213952".into(),
                }),
                password_hash: pw_hash.into(),
                public_key: "herp derp".into(),
                location: Some(Location {
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), true);
            assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

            let user = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&AuthRequest {
                user_id: user.user_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().user_id, user.user_id);

            future::ok(())
        }));
    }

    #[test]
    fn test_user_invalid_auth() {
        let _lock = LOCK.lock().unwrap();

        tokio::run(future::lazy(|| {
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

            future::ok(())
        }));
    }

    #[test]
    fn test_add_user_duplicate_email() {
        let _lock = LOCK.lock().unwrap();

        tokio::run(future::lazy(|| {
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
                    country_code: "US".into(),
                    national_number: "4013213953".into(),
                }),
                password_hash: pw_hash.into(),
                public_key: "herp derp".into(),
                location: Some(Location {
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), true);
            assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

            let user = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&AuthRequest {
                user_id: user.user_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().user_id, user.user_id);

            let result = rolodex.handle_add_user(&NewUserRequest {
                full_name: "Bob Marley".into(),
                email: "bob@aol.com".into(),
                phone_number: Some(PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213954".into(),
                }),
                password_hash: "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
                    .into(),
                public_key: "herp derp".into(),
                location: Some(Location {
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_err(), true);

            future::ok(())
        }));
    }

    #[test]
    fn test_add_user_duplicate_phone() {
        let _lock = LOCK.lock().unwrap();

        tokio::run(future::lazy(|| {
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
                    country_code: "US".into(),
                    national_number: "4013213953".into(),
                }),
                password_hash: pw_hash.into(),
                public_key: "herp derp".into(),
                location: Some(Location {
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), true);
            assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

            let user = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&AuthRequest {
                user_id: user.user_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().user_id, user.user_id);

            let result = rolodex.handle_add_user(&NewUserRequest {
                full_name: "Bob Marley".into(),
                email: "bob2@aol.com".into(),
                phone_number: Some(PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213953".into(),
                }),
                password_hash: "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86"
                    .into(),
                public_key: "herp derp".into(),
                location: Some(Location {
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_err(), true);
            assert_eq!(email_in_table(&db_pool, "bob2@aol.com"), false);

            future::ok(())
        }));
    }

    #[test]
    fn test_get_user() {
        let _lock = LOCK.lock().unwrap();

        tokio::run(future::lazy(|| {
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
                    country_code: "US".into(),
                    national_number: "4013213953".into(),
                }),
                password_hash: pw_hash.into(),
                public_key: "herp derp".into(),
                location: Some(Location {
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), true);
            assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

            let user = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&AuthRequest {
                user_id: user.user_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().user_id, user.user_id);

            let get_user = rolodex.handle_get_user(&GetUserRequest {
                user_id: user.user_id.to_string(),
                calling_user_id: user.user_id.to_string(),
            });

            assert_eq!(get_user.is_ok(), true);
            assert_eq!(get_user.unwrap().user_id, user.user_id);

            future::ok(())
        }));
    }
}
