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
        let counter = prometheus::IntCounter::new("client_added", "New client added").unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
    static ref USER_AUTHED: prometheus::IntCounter = {
        let counter =
            prometheus::IntCounter::new("client_authed", "Client authenticated successfully").unwrap();
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
    #[fail(display = "invalid client_id: {}", err)]
    InvalidClientId { err: String },
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
        RequestError::InvalidClientId {
            err: format!("{}", err),
        }
    }
}

impl From<Client> for rolodex_grpc::proto::GetClientResponse {
    fn from(client: Client) -> rolodex_grpc::proto::GetClientResponse {
        rolodex_grpc::proto::GetClientResponse {
            client_id: client.uuid.to_simple().to_string(),
            full_name: client.full_name,
            public_key: client.public_key,
        }
    }
}

impl From<Client> for rolodex_grpc::proto::AuthResponse {
    fn from(client: Client) -> rolodex_grpc::proto::AuthResponse {
        rolodex_grpc::proto::AuthResponse {
            client_id: client.uuid.to_simple().to_string(),
        }
    }
}

impl From<Client> for rolodex_grpc::proto::NewClientResponse {
    fn from(client: Client) -> rolodex_grpc::proto::NewClientResponse {
        rolodex_grpc::proto::NewClientResponse {
            client_id: client.uuid.to_simple().to_string(),
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

    /// Returns the client_id for this client if auth succeeds
    #[instrument(INFO)]
    fn handle_authenticate(&self, request: &AuthRequest) -> Result<AuthResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_reader.get().unwrap();

        let client: Client = clients::table
            .filter(
                clients::dsl::password_hash
                    .eq(crypt(
                        request.password_hash.clone(),
                        clients::dsl::password_hash,
                    ))
                    .and(clients::dsl::uuid.eq(&request_uuid)),
            )
            .first(&conn)?;

        USER_AUTHED.inc();
        Ok(client.into())
    }

    /// Returns the client_id for this client if account creation succeeded
    #[instrument(INFO)]
    fn handle_add_client(&self, request: &NewClientRequest) -> Result<NewClientResponse, RequestError> {
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
            clients::dsl::full_name.eq(request.full_name.clone()),
            clients::dsl::password_hash.eq(crypt(request.password_hash.clone(), gen_salt("bf", 8))),
            clients::dsl::phone_number.eq(number
                .format()
                .mode(phonenumber::Mode::International)
                .to_string()),
            clients::dsl::public_key.eq(request.public_key.clone()),
            clients::dsl::region.eq(region),
            clients::dsl::region_subdivision.eq(region_subdivision),
            clients::dsl::city.eq(city),
        );

        let conn = self.db_writer.get().unwrap();
        let client = conn.transaction::<_, Error, _>(|| {
            let client: Client = diesel::insert_into(clients::table)
                .values(&vec![fields])
                .get_result(&conn)?;

            let new_unique_email_address = NewUniqueEmailAddress {
                client_id: client.id,
                email_as_entered,
                email_without_labels,
            };

            diesel::insert_into(unique_email_addresses::table)
                .values(&new_unique_email_address)
                .execute(&conn)?;

            Ok(client)
        })?;

        USER_ADDED.inc();
        Ok(client.into())
    }

    /// Returns the client_id for this client if account creation succeeded
    #[instrument(INFO)]
    fn handle_get_client(&self, request: &GetClientRequest) -> Result<GetClientResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_reader.get().unwrap();

        let client: Client = clients::table
            .filter(clients::dsl::uuid.eq(&request_uuid))
            .first(&conn)?;

        Ok(client.into())
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

    type AddClientFuture =
        future::FutureResult<Response<NewClientResponse>, rolodex_grpc::tower_grpc::Status>;
    fn add_client(&mut self, request: Request<NewClientRequest>) -> Self::AddClientFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_add_client(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type GetClientFuture =
        future::FutureResult<Response<GetClientResponse>, rolodex_grpc::tower_grpc::Status>;
    fn get_client(&mut self, request: Request<GetClientRequest>) -> Self::GetClientFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_get_client(request.get_ref())
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

        empty_tables![unique_email_addresses, clients];
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
    fn test_add_client_valid() {
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

            let result = rolodex.handle_add_client(&NewClientRequest {
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

            let client = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&AuthRequest {
                client_id: client.client_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().client_id, client.client_id);

            future::ok(())
        }));
    }

    #[test]
    fn test_client_invalid_auth() {
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

            let client_id = "e9f272e503ff4b73891e77c766e8a251";
            let pw_hash = "419a636ccc2aa55c7347c79971a738c3103b34254bd79c1a3d767df62a788b86";

            let auth_result = rolodex.handle_authenticate(&AuthRequest {
                client_id: client_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_err(), true);

            future::ok(())
        }));
    }

    #[test]
    fn test_add_client_duplicate_email() {
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

            let result = rolodex.handle_add_client(&NewClientRequest {
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

            let client = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&AuthRequest {
                client_id: client.client_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().client_id, client.client_id);

            let result = rolodex.handle_add_client(&NewClientRequest {
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
    fn test_add_client_duplicate_phone() {
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

            let result = rolodex.handle_add_client(&NewClientRequest {
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

            let client = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&AuthRequest {
                client_id: client.client_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().client_id, client.client_id);

            let result = rolodex.handle_add_client(&NewClientRequest {
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
    fn test_get_client() {
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

            let result = rolodex.handle_add_client(&NewClientRequest {
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

            let client = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&AuthRequest {
                client_id: client.client_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().client_id, client.client_id);

            let get_client = rolodex.handle_get_client(&GetClientRequest {
                client_id: client.client_id.to_string(),
                calling_client_id: client.client_id.to_string(),
            });

            assert_eq!(get_client.is_ok(), true);
            assert_eq!(get_client.unwrap().client_id, client.client_id);

            future::ok(())
        }));
    }
}
