use crate::email;
use crate::models::*;
use crate::schema::*;
use diesel::prelude::*;
use diesel::result::Error;
use diesel::sql_types::{Integer, Text};
use email::Email;
use futures::future;
use instrumented::{instrument, prometheus, register};
use password_hash;
use rolodex_grpc::proto;
use rolodex_grpc::tower_grpc::{Request, Response};

fn make_intcounter(name: &str, description: &str) -> prometheus::IntCounter {
    let counter = prometheus::IntCounter::new(name, description).unwrap();
    register(Box::new(counter.clone())).unwrap();
    counter
}

lazy_static! {
    static ref CLIENT_ADDED: prometheus::IntCounter =
        make_intcounter("client_added", "New client added");
    static ref CLIENT_ADD_FAILED_INVALID_PHONE_NUMBER: prometheus::IntCounter = make_intcounter(
        "client_add_failed_invalid_phone_number",
        "Failed to add a client because of an invalid phone number",
    );
    static ref CLIENT_ADD_FAILED_PHONE_NUMBER_OMITTED: prometheus::IntCounter = make_intcounter(
        "client_add_failed_phone_number_omitted",
        "Failed to add a client because phone number was not specified",
    );
    static ref CLIENT_ADD_FAILED_INVALID_EMAIL: prometheus::IntCounter = make_intcounter(
        "client_add_failed_invaled_email",
        "Failed to add a client because of a bad email address",
    );
    static ref CLIENT_ADD_FAILED_DUPLICATE_EMAIL: prometheus::IntCounter = make_intcounter(
        "client_add_failed_duplicate_email",
        "Failed to add a client because of email address is a duplicate",
    );
    static ref CLIENT_ADD_FAILED_BANNED_EMAIL_DOMAIN: prometheus::IntCounter = make_intcounter(
        "client_add_failed_banned_email_domain",
        "Failed to add a client because email address is from a banned domain",
    );
    static ref CLIENT_ADD_FAILED_EMAIL_DOMAIN_INVALID_SUFFIX: prometheus::IntCounter =
        make_intcounter(
            "client_add_failed_email_domain_invalid_suffix",
            "Failed to add a client because email domain had an invalid suffix",
        );
    static ref CLIENT_ADD_FAILED_WEAK_PASSWORD: prometheus::IntCounter = make_intcounter(
        "client_add_failed_weak_password",
        "Failed to add a client because of a weak password",
    );
    static ref CLIENT_AUTHED: prometheus::IntCounter =
        make_intcounter("client_authed", "Client authenticated successfully");
    static ref CLIENT_UPDATED_PASSWORD: prometheus::IntCounter =
        make_intcounter("client_updated_password", "Client password updated");
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
    #[fail(display = "invalid password: {}", err)]
    InvalidPassword { err: String },
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

impl From<password_hash::PasswordHashError> for RequestError {
    fn from(err: password_hash::PasswordHashError) -> RequestError {
        RequestError::InvalidPassword {
            err: format!("{}", err),
        }
    }
}

impl From<email::EmailError> for RequestError {
    fn from(err: email::EmailError) -> RequestError {
        CLIENT_ADD_FAILED_INVALID_EMAIL.inc();
        match err {
            email::EmailError::BadFormat { email } => {
                CLIENT_ADD_FAILED_INVALID_EMAIL.inc();
                RequestError::InvalidEmail { email }
            }
            email::EmailError::BannedDomain { email } => {
                CLIENT_ADD_FAILED_BANNED_EMAIL_DOMAIN.inc();
                RequestError::InvalidEmail { email }
            }
            email::EmailError::InvalidSuffix { email } => {
                CLIENT_ADD_FAILED_EMAIL_DOMAIN_INVALID_SUFFIX.inc();
                RequestError::InvalidEmail { email }
            }
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
            client: Some(proto::Client {
                client_id: client.uuid.to_simple().to_string(),
                full_name: client.full_name,
                public_key: client.public_key,
            }),
        }
    }
}

impl From<Client> for proto::AuthResponse {
    fn from(client: Client) -> proto::AuthResponse {
        proto::AuthResponse {
            client_id: client.uuid.to_simple().to_string(),
        }
    }
}

impl From<Client> for proto::NewClientResponse {
    fn from(client: Client) -> proto::NewClientResponse {
        proto::NewClientResponse {
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
    fn handle_authenticate(
        &self,
        request: &proto::AuthRequest,
    ) -> Result<proto::AuthResponse, RequestError> {
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

        CLIENT_AUTHED.inc();
        Ok(client.into())
    }

    /// Returns the client_id for this client if account creation succeeded
    #[instrument(INFO)]
    fn handle_add_client(
        &self,
        request: &proto::NewClientRequest,
    ) -> Result<proto::NewClientResponse, RequestError> {
        use password_hash::PasswordHash;
        let number = if let Some(phone_number) = &request.phone_number {
            let country = phone_number.country_code.parse().unwrap();
            let number = phonenumber::parse(Some(country), &phone_number.national_number)?;
            let phonenumber_valid = number.is_valid();
            if !phonenumber_valid {
                CLIENT_ADD_FAILED_INVALID_PHONE_NUMBER.inc();
                return Err(RequestError::InvalidPhoneNumber {
                    err: number.to_string(),
                });
            }
            number
        } else {
            CLIENT_ADD_FAILED_PHONE_NUMBER_OMITTED.inc();
            return Err(RequestError::InvalidPhoneNumber {
                err: "no phone number specified".to_string(),
            });
        };

        let email: Email = request.email.to_lowercase().parse()?;
        let redis_conn = self.redis_reader.get()?;
        email.check_validity(&*redis_conn)?;

        let email_as_entered = email.email_as_entered.clone();
        let email_without_labels = email.email_without_labels.clone();

        let password_hash: PasswordHash = request.password_hash.parse()?;
        password_hash.check_validity(&*redis_conn)?;

        // let (region, region_subdivision, city) = if let Some(location) = &request.location {
        //     (
        //         Some(location.region.clone()),
        //         Some(location.region_subdivision.clone()),
        //         Some(location.city.clone()),
        //     )
        // } else {
        //     (None, None, None)
        // };

        let fields = (
            clients::dsl::full_name.eq(request.full_name.clone()),
            clients::dsl::password_hash.eq(crypt(password_hash.digest, gen_salt("bf", 8))),
            clients::dsl::phone_number.eq(number
                .format()
                .mode(phonenumber::Mode::International)
                .to_string()),
            clients::dsl::public_key.eq(request.public_key.clone()),
            // clients::dsl::region.eq(region),
            // clients::dsl::region_subdivision.eq(region_subdivision),
            // clients::dsl::city.eq(city),
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

        CLIENT_ADDED.inc();
        Ok(client.into())
    }

    /// Returns the client_id for this client if account creation succeeded
    #[instrument(INFO)]
    fn handle_get_client(
        &self,
        request: &proto::GetClientRequest,
    ) -> Result<proto::GetClientResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_reader.get().unwrap();

        let client: Client = clients::table
            .filter(clients::dsl::uuid.eq(&request_uuid))
            .first(&conn)?;

        Ok(client.into())
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_client(
        &self,
        request: &proto::UpdateClientRequest,
    ) -> Result<proto::UpdateClientResponse, RequestError> {
        Ok(proto::UpdateClientResponse {
            result: proto::Result::Success as i32,
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_client_password(
        &self,
        request: &proto::UpdateClientPasswordRequest,
    ) -> Result<proto::UpdateClientPasswordResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        use password_hash::PasswordHash;
        let password_hash: PasswordHash = request.password_hash.parse()?;
        let redis_conn = self.redis_reader.get()?;
        password_hash.check_validity(&*redis_conn)?;

        let conn = self.db_writer.get().unwrap();
        conn.transaction::<_, Error, _>(|| {
            diesel::update(clients::table.filter(clients::uuid.eq(request_uuid)))
                .set(clients::password_hash.eq(crypt(
                    request.password_hash.clone(),
                    clients::dsl::password_hash,
                )))
                .execute(&conn)?;

            // if let Some(location) = &request.location {
            //     // Update location data, if present
            //     diesel::update(clients::table.filter(clients::uuid.eq(request_uuid)))
            //         .set((
            //             clients::region.eq(Some(location.region.clone())),
            //             clients::region_subdivision.eq(Some(location.region_subdivision.clone())),
            //             clients::city.eq(Some(location.city.clone())),
            //         ))
            //         .execute(&conn)?;
            // }

            Ok(())
        })?;

        CLIENT_UPDATED_PASSWORD.inc();

        Ok(proto::UpdateClientPasswordResponse {
            result: proto::Result::Success as i32,
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_client_email(
        &self,
        request: &proto::UpdateClientEmailRequest,
    ) -> Result<proto::UpdateClientEmailResponse, RequestError> {
        Ok(proto::UpdateClientEmailResponse {
            result: proto::Result::Success as i32,
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_client_phone_number(
        &self,
        request: &proto::UpdateClientPhoneNumberRequest,
    ) -> Result<proto::UpdateClientPhoneNumberResponse, RequestError> {
        Ok(proto::UpdateClientPhoneNumberResponse {
            result: proto::Result::Success as i32,
        })
    }
}

impl proto::server::Rolodex for Rolodex {
    type AuthenticateFuture =
        future::FutureResult<Response<proto::AuthResponse>, rolodex_grpc::tower_grpc::Status>;
    fn authenticate(&mut self, request: Request<proto::AuthRequest>) -> Self::AuthenticateFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_authenticate(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type AddClientFuture =
        future::FutureResult<Response<proto::NewClientResponse>, rolodex_grpc::tower_grpc::Status>;
    fn add_client(&mut self, request: Request<proto::NewClientRequest>) -> Self::AddClientFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_add_client(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type GetClientFuture =
        future::FutureResult<Response<proto::GetClientResponse>, rolodex_grpc::tower_grpc::Status>;
    fn get_client(&mut self, request: Request<proto::GetClientRequest>) -> Self::GetClientFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_get_client(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type UpdateClientFuture = future::FutureResult<
        Response<proto::UpdateClientResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn update_client(
        &mut self,
        request: Request<proto::UpdateClientRequest>,
    ) -> Self::UpdateClientFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_update_client(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type UpdateClientPasswordFuture = future::FutureResult<
        Response<proto::UpdateClientPasswordResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn update_client_password(
        &mut self,
        request: Request<proto::UpdateClientPasswordRequest>,
    ) -> Self::UpdateClientPasswordFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_update_client_password(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type UpdateClientEmailFuture = future::FutureResult<
        Response<proto::UpdateClientEmailResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn update_client_email(
        &mut self,
        request: Request<proto::UpdateClientEmailRequest>,
    ) -> Self::UpdateClientEmailFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_update_client_email(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type UpdateClientPhoneNumberFuture = future::FutureResult<
        Response<proto::UpdateClientPhoneNumberResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn update_client_phone_number(
        &mut self,
        request: Request<proto::UpdateClientPhoneNumberRequest>,
    ) -> Self::UpdateClientPhoneNumberFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_update_client_phone_number(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type CheckFuture = future::FutureResult<
        Response<proto::HealthCheckResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn check(&mut self, _request: Request<proto::HealthCheckRequest>) -> Self::CheckFuture {
        future::ok(Response::new(proto::HealthCheckResponse {
            status: proto::health_check_response::ServingStatus::Serving as i32,
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

            let pw_hash = "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA";

            let result = rolodex.handle_add_client(&proto::NewClientRequest {
                full_name: "Bob Marley".into(),
                email: "bob@aol.com".into(),
                phone_number: Some(proto::PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213952".into(),
                }),
                password_hash: pw_hash.into(),
                public_key: "herp derp".into(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), true);
            assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

            let client = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&proto::AuthRequest {
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
            let pw_hash = "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA";

            let auth_result = rolodex.handle_authenticate(&proto::AuthRequest {
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

            let pw_hash = "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA";

            let result = rolodex.handle_add_client(&proto::NewClientRequest {
                full_name: "Bob Marley".into(),
                email: "bob@aol.com".into(),
                phone_number: Some(proto::PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213953".into(),
                }),
                password_hash: pw_hash.into(),
                public_key: "herp derp".into(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), true);
            assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

            let client = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&proto::AuthRequest {
                client_id: client.client_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().client_id, client.client_id);

            let result = rolodex.handle_add_client(&proto::NewClientRequest {
                full_name: "Bob Marley".into(),
                email: "bob@aol.com".into(),
                phone_number: Some(proto::PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213954".into(),
                }),
                password_hash: "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA"
                    .into(),
                public_key: "herp derp".into(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
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

            let pw_hash = "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA";

            let result = rolodex.handle_add_client(&proto::NewClientRequest {
                full_name: "Bob Marley".into(),
                email: "bob@aol.com".into(),
                phone_number: Some(proto::PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213953".into(),
                }),
                password_hash: pw_hash.into(),
                public_key: "herp derp".into(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), true);
            assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

            let client = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&proto::AuthRequest {
                client_id: client.client_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().client_id, client.client_id);

            let result = rolodex.handle_add_client(&proto::NewClientRequest {
                full_name: "Bob Marley".into(),
                email: "bob2@aol.com".into(),
                phone_number: Some(proto::PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213953".into(),
                }),
                password_hash: "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA"
                    .into(),
                public_key: "herp derp".into(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
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

            let pw_hash = "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA";

            let result = rolodex.handle_add_client(&proto::NewClientRequest {
                full_name: "Bob Marley".into(),
                email: "bob@aol.com".into(),
                phone_number: Some(proto::PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213953".into(),
                }),
                password_hash: pw_hash.into(),
                public_key: "herp derp".into(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), true);
            assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

            let client = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&proto::AuthRequest {
                client_id: client.client_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().client_id, client.client_id);

            let get_client = rolodex.handle_get_client(&proto::GetClientRequest {
                client_id: client.client_id.to_string(),
                calling_client_id: client.client_id.to_string(),
            });

            assert_eq!(get_client.is_ok(), true);
            assert_eq!(
                get_client.unwrap().client.unwrap().client_id,
                client.client_id
            );

            future::ok(())
        }));
    }

    #[test]
    fn test_add_client_update_password() {
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

            let pw_hash = "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7MA";

            let result = rolodex.handle_add_client(&proto::NewClientRequest {
                full_name: "Bob Marley".into(),
                email: "bob@aol.com".into(),
                phone_number: Some(proto::PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213952".into(),
                }),
                password_hash: pw_hash.into(),
                public_key: "herp derp".into(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), true);
            assert_eq!(email_in_table(&db_pool, "bob@aol.com"), true);

            let client = result.unwrap();

            let auth_result = rolodex.handle_authenticate(&proto::AuthRequest {
                client_id: client.client_id.to_string(),
                password_hash: pw_hash.into(),
            });
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().client_id, client.client_id);

            let new_pw = "HhG3RQhBk/2FWMwqQ9OadQv+WbzoB3eho99MWephbHOgL2S+zT0mN9GHepVOTQy8YCUn3YfBtHmp6v5AKIL7LA";

            // Update password
            let update_result =
                rolodex.handle_update_client_password(&proto::UpdateClientPasswordRequest {
                    client_id: client.client_id.to_string(),
                    password_hash: new_pw.into(),
                    location: None,
                });

            if update_result.is_err() {
                panic!("err: {:?}", update_result.err());
            }
            assert_eq!(update_result.is_ok(), true);
            assert_eq!(update_result.unwrap().result, proto::Result::Success as i32);

            // Login with new password
            let auth_result = rolodex.handle_authenticate(&proto::AuthRequest {
                client_id: client.client_id.to_string(),
                password_hash: new_pw.into(),
            });
            if auth_result.is_err() {
                panic!("err: {:?}", auth_result.err());
            }
            assert_eq!(auth_result.is_ok(), true);
            assert_eq!(auth_result.unwrap().client_id, client.client_id);
            future::ok(())
        }));
    }
}
