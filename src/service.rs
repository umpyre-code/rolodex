use crate::email;
use crate::models;
use crate::sanitizers;
use crate::schema;
use crate::sql_types::*;

use diesel::prelude::*;
use diesel::result::Error;
use email::Email;
use futures::future;
use instrumented::{instrument, prometheus, register};
use rolodex_grpc::proto;
use rolodex_grpc::tower_grpc::{Request, Response};

pub fn make_intcounter(name: &str, description: &str) -> prometheus::IntCounter {
    let counter = prometheus::IntCounter::new(name, description).unwrap();
    register(Box::new(counter.clone())).unwrap();
    counter
}

lazy_static! {
    static ref CLIENT_ADDED: prometheus::IntCounter =
        make_intcounter("client_added_total", "New client added");
    static ref CLIENT_PHONE_VERIFIED: prometheus::IntCounter = make_intcounter(
        "client_phone_verified_total",
        "Client phone verified via SMS"
    );
    static ref CLIENT_PHONE_VERIFY_BAD_CODE: prometheus::IntCounter = make_intcounter(
        "client_phone_verify_bad_code_total",
        "Client phone verification failed due to bad code"
    );
    static ref CLIENT_UPDATE_FAILED: prometheus::IntCounterVec = {
        let counter_opts =
            prometheus::Opts::new("client_update_failed_total", "Failed to update a client");
        let counter = prometheus::IntCounterVec::new(counter_opts, &["reason"]).unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
    static ref CLIENT_ADD_FAILED: prometheus::IntCounterVec = {
        let counter_opts =
            prometheus::Opts::new("client_add_failed_total", "Failed to add a client");
        let counter = prometheus::IntCounterVec::new(counter_opts, &["reason"]).unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
    static ref CLIENT_AUTHED: prometheus::IntCounter =
        make_intcounter("client_authed_total", "Client authenticated successfully");
    static ref CLIENT_UPDATED: prometheus::IntCounter =
        make_intcounter("client_updated_total", "Client account data updated");
    static ref CLIENT_UPDATED_PASSWORD: prometheus::IntCounter =
        make_intcounter("client_updated_password_total", "Client password updated");
    static ref CLIENT_UPDATED_EMAIL: prometheus::IntCounter =
        make_intcounter("client_updated_email_total", "Client email address updated");
    static ref CLIENT_UPDATED_PHONE_NUMBER: prometheus::IntCounter = make_intcounter(
        "client_updated_phone_number_total",
        "Client phone number updated"
    );
}

#[derive(Clone)]
pub struct Rolodex {
    db_reader: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
    db_writer: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
    redis_reader: r2d2_redis_cluster::r2d2::Pool<r2d2_redis_cluster::RedisClusterConnectionManager>,
    redis_writer: r2d2_redis_cluster::r2d2::Pool<r2d2_redis_cluster::RedisClusterConnectionManager>,
}

#[derive(Debug, Fail)]
enum RequestError {
    #[fail(display = "invalid phone number: {}", err)]
    InvalidPhoneNumber { err: String },
    #[fail(display = "invalid email: {}", email)]
    InvalidEmail { email: String },
    #[fail(display = "invalid password: {}", err)]
    InvalidPassword { err: String },
    #[fail(display = "unique violation")]
    UniqueViolation,
    #[fail(display = "database error: {}", err)]
    DatabaseError { err: String },
    #[fail(display = "email domain DNS failure: {}", err)]
    EmailDNSFailure { err: String },
    #[fail(display = "invalid client_id: {}", err)]
    InvalidClientId { err: String },
    #[fail(display = "resource could not be found")]
    NotFound,
    #[fail(display = "Bad arguments specified for request")]
    BadArguments,
}

#[derive(Debug, QueryableByName)]
pub struct AmountByDateQueryResult {
    #[sql_type = "diesel::sql_types::BigInt"]
    pub count: i64,
    #[sql_type = "diesel::sql_types::Date"]
    pub ds: chrono::NaiveDate,
}

#[derive(Debug, QueryableByName)]
pub struct AmountByClientQueryResult {
    #[sql_type = "diesel::sql_types::BigInt"]
    pub amount_cents: i64,
    #[sql_type = "diesel::sql_types::Uuid"]
    pub client_id: uuid::Uuid,
}

impl From<diesel::result::Error> for RequestError {
    fn from(err: diesel::result::Error) -> RequestError {
        match err {
            diesel::result::Error::NotFound => RequestError::NotFound,
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => RequestError::UniqueViolation,
            _ => RequestError::DatabaseError {
                err: format!("{}", err),
            },
        }
    }
}

impl From<r2d2_redis_cluster::r2d2::Error> for RequestError {
    fn from(err: r2d2_redis_cluster::r2d2::Error) -> RequestError {
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

impl From<r2d2_redis_cluster::redis_cluster_rs::redis::RedisError> for RequestError {
    fn from(err: r2d2_redis_cluster::redis_cluster_rs::redis::RedisError) -> RequestError {
        RequestError::DatabaseError {
            err: format!("{}", err),
        }
    }
}

impl From<srp::types::SrpAuthError> for RequestError {
    fn from(err: srp::types::SrpAuthError) -> RequestError {
        RequestError::InvalidPassword {
            err: format!("{}", err),
        }
    }
}

impl From<email::EmailError> for RequestError {
    fn from(err: email::EmailError) -> RequestError {
        CLIENT_ADD_FAILED
            .with_label_values(&["invalid email"])
            .inc();
        match err {
            email::EmailError::BadFormat { email } => {
                CLIENT_ADD_FAILED
                    .with_label_values(&["invalid email"])
                    .inc();
                RequestError::InvalidEmail { email }
            }
            email::EmailError::BannedDomain { email } => {
                CLIENT_ADD_FAILED
                    .with_label_values(&["banned email domain"])
                    .inc();
                RequestError::InvalidEmail { email }
            }
            email::EmailError::InvalidSuffix { email } => {
                CLIENT_ADD_FAILED
                    .with_label_values(&["invalid suffix"])
                    .inc();
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

impl From<models::Client> for rolodex_grpc::proto::GetClientResponse {
    fn from(client: models::Client) -> rolodex_grpc::proto::GetClientResponse {
        rolodex_grpc::proto::GetClientResponse {
            client: Some(client.into()),
        }
    }
}

impl From<models::Client> for proto::NewClientResponse {
    fn from(client: models::Client) -> proto::NewClientResponse {
        proto::NewClientResponse {
            client_id: client.uuid.to_simple().to_string(),
            referred_by: match client.referred_by {
                Some(uuid) => uuid.to_simple().to_string(),
                None => "".into(),
            },
        }
    }
}

impl From<models::Client> for proto::Client {
    fn from(client: models::Client) -> proto::Client {
        proto::Client {
            box_public_key: client.box_public_key,
            client_id: client.uuid.to_simple().to_string(),
            full_name: client.full_name,
            handle: client.handle.unwrap_or_else(|| String::from("")),
            profile: client.profile.unwrap_or_else(|| String::from("")),
            signing_public_key: client.signing_public_key,
            joined: client.created_at.timestamp(),
            phone_sms_verified: client.phone_sms_verified,
            ral: client.ral,
            avatar_version: client.avatar_version,
            referred_by: match client.referred_by {
                Some(uuid) => uuid.to_simple().to_string(),
                None => "".into(),
            },
        }
    }
}

impl From<&models::Client> for proto::Client {
    fn from(client: &models::Client) -> proto::Client {
        proto::Client {
            box_public_key: client.box_public_key.clone(),
            client_id: client.uuid.to_simple().to_string(),
            full_name: client.full_name.clone(),
            handle: client
                .handle
                .as_ref()
                .cloned()
                .unwrap_or_else(|| String::from("")),
            profile: client
                .profile
                .as_ref()
                .cloned()
                .unwrap_or_else(|| String::from("")),
            signing_public_key: client.signing_public_key.clone(),
            joined: client.created_at.timestamp(),
            phone_sms_verified: client.phone_sms_verified,
            ral: client.ral,
            avatar_version: client.avatar_version,
            referred_by: match client.referred_by {
                Some(uuid) => uuid.to_simple().to_string(),
                None => "".into(),
            },
        }
    }
}

impl From<models::ClientPrefs> for proto::Prefs {
    fn from(prefs: models::ClientPrefs) -> Self {
        Self {
            email_notifications: match prefs.email_notifications {
                EmailNotificationsPref::Never => "never".into(),
                EmailNotificationsPref::Ral => "ral".into(),
                EmailNotificationsPref::Always => "always".into(),
            },
            include_in_leaderboard: prefs.include_in_leaderboard,
        }
    }
}

impl From<&proto::Prefs> for models::UpdateClientPrefs {
    fn from(prefs: &proto::Prefs) -> Self {
        Self {
            email_notifications: match prefs.email_notifications.as_ref() {
                "never" => EmailNotificationsPref::Never,
                "ral" => EmailNotificationsPref::Ral,
                "always" => EmailNotificationsPref::Always,
                _ => EmailNotificationsPref::Ral,
            },
            include_in_leaderboard: prefs.include_in_leaderboard,
        }
    }
}

fn insert_client_action(
    client_id: i64,
    action: ClientAccountAction,
    location: &Option<proto::Location>,
    conn: &diesel::pg::PgConnection,
) -> Result<(), Error> {
    let (ip_address, region, region_subdivision, city) = if let Some(location) = location {
        (
            Some(location.ip_address.clone()),
            Some(location.region.clone()),
            Some(location.region_subdivision.clone()),
            Some(location.city.clone()),
        )
    } else {
        (None, None, None, None)
    };

    let client_action = models::NewClientAccountAction {
        client_id,
        action,
        ip_address,
        region,
        region_subdivision,
        city,
    };

    diesel::insert_into(schema::client_account_actions::table)
        .values(&client_action)
        .execute(conn)?;

    Ok(())
}

fn validate_phone_number(
    phone_number: &Option<proto::PhoneNumber>,
) -> Result<String, RequestError> {
    if let Some(phone_number) = phone_number {
        let country = phone_number.country_code.parse().unwrap();
        let number = phonenumber::parse(Some(country), &phone_number.national_number)?;
        let phonenumber_valid = number.is_valid();
        if !phonenumber_valid {
            CLIENT_UPDATE_FAILED
                .with_label_values(&["invalid phone number"])
                .inc();
            return Err(RequestError::InvalidPhoneNumber {
                err: number.to_string(),
            });
        }
        Ok(number
            .format()
            .mode(phonenumber::Mode::International)
            .to_string())
    } else {
        CLIENT_UPDATE_FAILED
            .with_label_values(&["phone number omitted"])
            .inc();
        Err(RequestError::InvalidPhoneNumber {
            err: "no phone number specified".to_string(),
        })
    }
}

fn generate_and_send_verification_code(client: &models::Client) -> i32 {
    use crate::messagebird::Client;
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let code = rng.gen_range(100_000, 1_000_000);

    let sms_client = Client::new();

    let body = format!(
        "Umpyre verification code: {:03}-{:03}",
        code / 1000,
        code % 1000
    );

    let result = sms_client.send_sms(&client.phone_country_code, &client.phone_number, &body);
    if result.is_err() {
        error!("sms send error: {:?}", result.unwrap_err());
    }

    code
}

impl Rolodex {
    pub fn new(
        db_reader: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        db_writer: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        redis_reader: r2d2_redis_cluster::r2d2::Pool<
            r2d2_redis_cluster::RedisClusterConnectionManager,
        >,
        redis_writer: r2d2_redis_cluster::r2d2::Pool<
            r2d2_redis_cluster::RedisClusterConnectionManager,
        >,
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
    fn handle_auth_handshake(
        &self,
        request: &proto::AuthHandshakeRequest,
    ) -> Result<proto::AuthHandshakeResponse, RequestError> {
        use crate::config;
        use data_encoding::BASE64URL_NOPAD;
        use r2d2_redis_cluster::redis_cluster_rs::redis;
        use r2d2_redis_cluster::redis_cluster_rs::redis::RedisResult;
        use r2d2_redis_cluster::Commands;
        use rand::rngs::OsRng;
        use rand::RngCore;
        use sha2::Sha256;
        use srp::groups::G_2048;
        use srp::server::{SrpServer, UserRecord};

        let email = request.email.clone();

        // Retrieve client auth info
        let conn = self.db_reader.get().unwrap();

        // Find client_id, if it exists
        match schema::unique_email_addresses::table
            .filter(schema::unique_email_addresses::dsl::email_as_entered.eq(&email))
            .first::<models::UniqueEmailAddress>(&conn)
        {
            Ok(unique_email_address) => {
                let client_pk_id = unique_email_address.client_id;

                let client: models::ClientAuth = schema::clients::table
                    .select((
                        schema::clients::dsl::id,
                        schema::clients::dsl::uuid,
                        schema::clients::dsl::password_verifier,
                        schema::clients::dsl::password_salt,
                    ))
                    .filter(schema::clients::dsl::id.eq(client_pk_id))
                    .first(&conn)?;

                let mut b = vec![0u8; 64];
                OsRng.fill_bytes(&mut b);

                let mut redis_conn = self.redis_writer.get()?;

                let auth_key = format!("auth:{}:{}", email, BASE64URL_NOPAD.encode(&request.a_pub));
                redis_conn.set_ex(auth_key.clone(), BASE64URL_NOPAD.encode(&b), 300)?;
                let _result: (i32) = redis::cmd("WAIT")
                    .arg(config::CONFIG.redis.replicas_per_master)
                    .arg(0)
                    .query(&mut (*redis_conn))?;

                let user = UserRecord {
                    username: email.as_bytes(),
                    salt: &client.password_salt,
                    verifier: &client.password_verifier,
                };

                let server = SrpServer::<Sha256>::new(&user, &request.a_pub, &b, &G_2048)?;
                let b_pub = server.get_b_pub();

                Ok(proto::AuthHandshakeResponse {
                    email,
                    salt: client.password_salt,
                    b_pub,
                })
            }
            Err(_err) => {
                let mut b_pub = vec![0u8; 256];
                OsRng.fill_bytes(&mut b_pub);

                let mut salt = vec![0u8; 16];
                OsRng.fill_bytes(&mut salt);

                Ok(proto::AuthHandshakeResponse { email, salt, b_pub })
            }
        }
    }

    /// Returns the client_id for this client if auth succeeds
    #[instrument(INFO)]
    fn handle_auth_verify(
        &self,
        request: &proto::AuthVerifyRequest,
    ) -> Result<proto::AuthVerifyResponse, RequestError> {
        use data_encoding::BASE64URL_NOPAD;
        use r2d2_redis_cluster::redis_cluster_rs::redis::RedisResult;
        use r2d2_redis_cluster::Commands;
        use rolodex_grpc::proto::AuthVerifyResponse;
        use sha2::Sha256;
        use srp::groups::G_2048;
        use srp::server::{SrpServer, UserRecord};

        let email = request.email.clone();

        // We read from the writer in this case, because sometimes we can get
        // stale reads on the replica instance.
        let mut redis_conn = self.redis_reader.get()?;

        let key = format!("auth:{}:{}", email, BASE64URL_NOPAD.encode(&request.a_pub));

        let response: RedisResult<String> = redis_conn.get(key.clone());

        let b = match response {
            Ok(response) => BASE64URL_NOPAD.decode(response.as_bytes()).unwrap(),
            _ => {
                return Err(RequestError::InvalidPassword {
                    err: "could not retrieve key".into(),
                })
            }
        };

        // Retrieve client auth info
        let conn = self.db_reader.get().unwrap();

        // Find client_id, if it exists
        let unique_email_address: models::UniqueEmailAddress =
            match schema::unique_email_addresses::table
                .filter(schema::unique_email_addresses::dsl::email_as_entered.eq(&email))
                .first(&conn)
            {
                Ok(result) => result,
                _ => return Err(RequestError::BadArguments),
            };

        let client_pk_id = unique_email_address.client_id;

        let client: models::ClientAuth = schema::clients::table
            .select((
                schema::clients::dsl::id,
                schema::clients::dsl::uuid,
                schema::clients::dsl::password_verifier,
                schema::clients::dsl::password_salt,
            ))
            .filter(schema::clients::dsl::id.eq(client_pk_id))
            .first(&conn)?;

        let user = UserRecord {
            username: email.as_bytes(),
            salt: &client.password_salt,
            verifier: &client.password_verifier,
        };

        let server = SrpServer::<Sha256>::new(&user, &request.a_pub, &b, &G_2048)?;

        let conn = self.db_writer.get().unwrap();

        insert_client_action(
            client.id,
            ClientAccountAction::Authenticated,
            &request.location,
            &conn,
        )?;

        CLIENT_AUTHED.inc();
        Ok(AuthVerifyResponse {
            client_id: client.uuid.to_simple().to_string(),
            server_proof: server.verify(&request.client_proof)?.to_vec(),
            session_key: server.get_key().to_vec(),
        })
    }

    /// Returns the client_id for this client if account creation succeeded
    #[instrument(INFO)]
    fn handle_add_client(
        &self,
        request: &proto::NewClientRequest,
    ) -> Result<proto::NewClientResponse, RequestError> {
        use std::{thread, time};

        let phone_number = validate_phone_number(&request.phone_number)?;

        let email: Email = request.email.to_lowercase().parse()?;
        let mut redis_conn = self.redis_reader.get()?;
        email.check_validity(&mut *redis_conn)?;

        let email_as_entered = email.email_as_entered.clone();
        let email_without_labels = email.email_without_labels.clone();

        let referred_by = if !request.referred_by.is_empty() {
            let conn = self.db_reader.get().unwrap();
            // check account exists
            match uuid::Uuid::parse_str(&request.referred_by) {
                Ok(ref_uuid) => {
                    let ref_client: Result<models::Client, diesel::result::Error> =
                        schema::clients::table
                            .filter(schema::clients::dsl::uuid.eq(&ref_uuid))
                            .first(&conn);
                    match ref_client {
                        Ok(_) => Some(ref_uuid),
                        Err(_) => None,
                    }
                }
                Err(_) => None,
            }
        } else {
            None
        };

        let new_client = models::NewClient {
            full_name: sanitizers::full_name(&request.full_name),
            password_verifier: request.password_verifier.clone(),
            password_salt: request.password_salt.clone(),
            phone_number,
            box_public_key: sanitizers::public_key(&request.box_public_key),
            signing_public_key: sanitizers::public_key(&request.signing_public_key),
            phone_country_code: request.phone_number.as_ref().unwrap().country_code.clone(),
            referred_by,
        };

        let conn = self.db_writer.get().unwrap();
        let client = conn.transaction::<_, Error, _>(|| {
            let client: models::Client = diesel::insert_into(schema::clients::table)
                .values(&new_client)
                .get_result(&conn)?;

            let new_unique_email_address = models::NewUniqueEmailAddress {
                client_id: client.id,
                email_as_entered,
                email_without_labels,
            };

            diesel::insert_into(schema::unique_email_addresses::table)
                .values(&new_unique_email_address)
                .execute(&conn)?;

            let code = generate_and_send_verification_code(&client);
            let new_phone_verification_code = models::NewPhoneVerificationCode {
                client_id: client.id,
                code,
            };

            diesel::insert_into(schema::phone_verification_codes::table)
                .values(&new_phone_verification_code)
                .execute(&conn)?;

            insert_client_action(
                client.id,
                ClientAccountAction::Created,
                &request.location,
                &conn,
            )?;

            Ok(client)
        })?;

        // lastly, wait until new client is visible on read replica(s) before returning.
        let mut client_replicated = false;
        while !client_replicated {
            let conn = self.db_reader.get().unwrap();
            let new_client: Result<models::Client, Error> = schema::clients::table
                .filter(schema::clients::uuid.eq(client.uuid))
                .first(&conn);
            client_replicated = match new_client {
                Ok(_) => true,
                Err(_) => {
                    let fifty_millis = time::Duration::from_millis(50);
                    thread::sleep(fifty_millis);
                    false
                }
            };
        }

        CLIENT_ADDED.inc();
        Ok(client.into())
    }

    /// Returns the client_id for this client if account creation succeeded
    #[instrument(INFO)]
    fn handle_get_client(
        &self,
        request: &proto::GetClientRequest,
    ) -> Result<proto::GetClientResponse, RequestError> {
        match &request.id {
            Some(proto::get_client_request::Id::ClientId(client_id)) => {
                let request_uuid = uuid::Uuid::parse_str(&client_id)?;

                let conn = self.db_reader.get().unwrap();

                let client: models::Client = schema::clients::table
                    .filter(schema::clients::dsl::uuid.eq(&request_uuid))
                    .first(&conn)?;

                Ok(client.into())
            }
            Some(proto::get_client_request::Id::Handle(handle)) => {
                let conn = self.db_reader.get().unwrap();
                let handle_lowercase = sanitizers::handle(&handle).to_lowercase();

                let client: models::Client = schema::clients::table
                    .filter(schema::clients::dsl::handle_lowercase.eq(&handle_lowercase))
                    .first(&conn)?;

                Ok(client.into())
            }
            _ => Err(RequestError::NotFound),
        }
    }

    /// Returns the client_id for this client if account creation succeeded
    #[instrument(INFO)]
    fn handle_get_client_email(
        &self,
        request: &proto::GetClientEmailRequest,
    ) -> Result<proto::GetClientEmailResponse, RequestError> {
        use models::UniqueEmailAddress;

        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_reader.get().unwrap();

        let client: models::Client = schema::clients::table
            .filter(schema::clients::dsl::uuid.eq(&request_uuid))
            .first(&conn)?;

        let email: UniqueEmailAddress = UniqueEmailAddress::belonging_to(&client).first(&conn)?;

        Ok(proto::GetClientEmailResponse {
            client_id: request.client_id.clone(),
            email_as_entered: email.email_as_entered,
            email_without_labels: email.email_without_labels,
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_client(
        &self,
        request: &proto::UpdateClientRequest,
    ) -> Result<proto::UpdateClientResponse, RequestError> {
        use crate::optional::Optional;
        let client = if let Some(client) = &request.client {
            client.clone()
        } else {
            return Err(RequestError::BadArguments);
        };

        let request_uuid = uuid::Uuid::parse_str(&client.client_id)?;

        let updated_client = models::UpdateClient {
            full_name: sanitizers::full_name(&client.full_name),
            box_public_key: sanitizers::public_key(&client.box_public_key),
            signing_public_key: sanitizers::public_key(&client.signing_public_key),
            profile: sanitizers::profile(&client.profile).into_option(),
            handle: sanitizers::handle(&client.handle).into_option(),
            handle_lowercase: sanitizers::handle(&client.handle)
                .to_lowercase()
                .into_option(),
        };

        let conn = self.db_writer.get().unwrap();
        let updated_row = conn.transaction::<_, Error, _>(|| {
            let updated_row: models::Client = diesel::update(
                schema::clients::table.filter(schema::clients::uuid.eq(request_uuid)),
            )
            .set(&updated_client)
            .get_result(&conn)?;

            insert_client_action(
                updated_row.id,
                ClientAccountAction::Updated,
                &request.location,
                &conn,
            )?;

            Ok(updated_row)
        })?;

        CLIENT_UPDATED.inc();

        Ok(proto::UpdateClientResponse {
            result: proto::Result::Success as i32,
            client: Some(updated_row.into()),
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_client_ral(
        &self,
        request: &proto::UpdateClientRalRequest,
    ) -> Result<proto::UpdateClientResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_writer.get().unwrap();
        let client = conn.transaction::<models::Client, Error, _>(|| {
            let updated_row: models::Client = diesel::update(
                schema::clients::table.filter(schema::clients::uuid.eq(request_uuid)),
            )
            .set((schema::clients::ral.eq(request.ral),))
            .get_result(&conn)?;

            Ok(updated_row)
        })?;

        CLIENT_UPDATED_PASSWORD.inc();

        Ok(proto::UpdateClientResponse {
            result: proto::Result::Success as i32,
            client: Some(client.into()),
        })
    }

    // Increment a client's avatar version
    #[instrument(INFO)]
    fn handle_increment_client_avatar(
        &self,
        request: &proto::IncrementClientAvatarRequest,
    ) -> Result<proto::UpdateClientResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_writer.get().unwrap();
        let client = conn.transaction::<models::Client, Error, _>(|| {
            let updated_row: models::Client = diesel::update(
                schema::clients::table.filter(schema::clients::uuid.eq(request_uuid)),
            )
            .set((schema::clients::avatar_version
                .eq(schema::clients::avatar_version + request.increment_by),))
            .get_result(&conn)?;

            Ok(updated_row)
        })?;

        CLIENT_UPDATED_PASSWORD.inc();

        Ok(proto::UpdateClientResponse {
            result: proto::Result::Success as i32,
            client: Some(client.into()),
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_client_password(
        &self,
        request: &proto::UpdateClientPasswordRequest,
    ) -> Result<proto::UpdateClientResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_writer.get().unwrap();
        let client = conn.transaction::<models::Client, Error, _>(|| {
            let updated_row: models::Client = diesel::update(
                schema::clients::table.filter(schema::clients::uuid.eq(request_uuid)),
            )
            .set((
                schema::clients::password_verifier.eq(request.password_verifier.clone()),
                schema::clients::password_salt.eq(request.password_salt.clone()),
            ))
            .get_result(&conn)?;

            insert_client_action(
                updated_row.id,
                ClientAccountAction::PasswordUpdated,
                &request.location,
                &conn,
            )?;

            Ok(updated_row)
        })?;

        CLIENT_UPDATED_PASSWORD.inc();

        Ok(proto::UpdateClientResponse {
            result: proto::Result::Success as i32,
            client: Some(client.into()),
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_client_email(
        &self,
        request: &proto::UpdateClientEmailRequest,
    ) -> Result<proto::UpdateClientResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let email: Email = request.email.to_lowercase().parse()?;
        let mut redis_conn = self.redis_reader.get()?;
        email.check_validity(&mut *redis_conn)?;

        let email_as_entered = email.email_as_entered.clone();
        let email_without_labels = email.email_without_labels.clone();

        let conn = self.db_writer.get().unwrap();
        let client = conn.transaction::<models::Client, Error, _>(|| {
            let client: models::Client = schema::clients::table
                .filter(schema::clients::dsl::uuid.eq(&request_uuid))
                .first(&conn)?;

            // Delete the old email address first
            diesel::delete(
                schema::unique_email_addresses::table
                    .filter(schema::unique_email_addresses::client_id.eq(client.id)),
            )
            .execute(&conn)?;

            let new_unique_email_address = models::NewUniqueEmailAddress {
                client_id: client.id,
                email_as_entered,
                email_without_labels,
            };

            // Insert new email address
            diesel::insert_into(schema::unique_email_addresses::table)
                .values(&new_unique_email_address)
                .execute(&conn)?;

            insert_client_action(
                client.id,
                ClientAccountAction::EmailUpdated,
                &request.location,
                &conn,
            )?;

            let client: models::Client = schema::clients::table
                .filter(schema::clients::dsl::uuid.eq(&request_uuid))
                .first(&conn)?;

            Ok(client)
        })?;

        CLIENT_UPDATED_EMAIL.inc();

        Ok(proto::UpdateClientResponse {
            result: proto::Result::Success as i32,
            client: Some(client.into()),
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_client_phone_number(
        &self,
        request: &proto::UpdateClientPhoneNumberRequest,
    ) -> Result<proto::UpdateClientResponse, RequestError> {
        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_writer.get().unwrap();
        let client = conn.transaction::<models::Client, Error, _>(|| {
            let updated_row: models::Client = diesel::update(
                schema::clients::table.filter(schema::clients::uuid.eq(request_uuid)),
            )
            .set(schema::clients::phone_sms_verified.eq(true))
            .get_result(&conn)?;

            insert_client_action(
                updated_row.id,
                ClientAccountAction::PhoneNumberUpdated,
                &request.location,
                &conn,
            )?;

            Ok(updated_row)
        })?;

        CLIENT_UPDATED_PHONE_NUMBER.inc();

        Ok(proto::UpdateClientResponse {
            result: proto::Result::Success as i32,
            client: Some(client.into()),
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_verify_phone(
        &self,
        request: &proto::VerifyPhoneRequest,
    ) -> Result<proto::VerifyPhoneResponse, RequestError> {
        use crate::config;
        use crate::models::PhoneVerificationCode;
        use crate::schema::clients::columns::{phone_sms_verified, uuid as client_uuid};
        use crate::schema::clients::table as clients;

        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_reader.get().unwrap();
        let client: models::Client = clients.filter(client_uuid.eq(request_uuid)).first(&conn)?;
        let db_code: PhoneVerificationCode =
            PhoneVerificationCode::belonging_to(&client).first(&conn)?;

        if config::CONFIG.messagebird.verification_enforced && db_code.code != request.code {
            CLIENT_PHONE_VERIFY_BAD_CODE.inc();
            Ok(proto::VerifyPhoneResponse {
                result: proto::Result::Failure as i32,
                client: Some(client.into()),
            })
        } else {
            let conn = self.db_writer.get().unwrap();
            let client = conn.transaction::<models::Client, Error, _>(|| {
                let updated_row: models::Client =
                    diesel::update(clients.filter(client_uuid.eq(request_uuid)))
                        .set(phone_sms_verified.eq(true))
                        .get_result(&conn)?;

                insert_client_action(
                    updated_row.id,
                    ClientAccountAction::PhoneVerified,
                    &request.location,
                    &conn,
                )?;

                Ok(updated_row)
            })?;

            CLIENT_PHONE_VERIFIED.inc();

            Ok(proto::VerifyPhoneResponse {
                result: proto::Result::Success as i32,
                client: Some(client.into()),
            })
        }
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_send_verification_code(
        &self,
        request: &proto::SendVerificationCodeRequest,
    ) -> Result<proto::SendVerificationCodeResponse, RequestError> {
        use crate::models::PhoneVerificationCode;
        use crate::schema::clients::columns::uuid as client_uuid;
        use crate::schema::clients::table as clients;
        use crate::schema::phone_verification_codes::table as phone_verification_codes;
        use chrono::prelude::*;
        use diesel::update;

        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_reader.get().unwrap();
        let client: models::Client = clients.filter(client_uuid.eq(request_uuid)).first(&conn)?;
        let db_code: PhoneVerificationCode =
            PhoneVerificationCode::belonging_to(&client).first(&conn)?;

        let duration = Utc::now().naive_utc() - db_code.updated_at;

        // Don't send more than 1 code very 120 seconds (2 minutes)
        if duration.num_seconds() > 120 {
            let code = generate_and_send_verification_code(&client);

            let conn = self.db_writer.get().unwrap();
            update(
                phone_verification_codes
                    .filter(crate::schema::phone_verification_codes::columns::id.eq(db_code.id)),
            )
            .set(crate::schema::phone_verification_codes::columns::code.eq(code))
            .execute(&conn)?;
        }

        Ok(proto::SendVerificationCodeResponse {})
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_get_prefs(
        &self,
        request: &proto::GetPrefsRequest,
    ) -> Result<proto::GetPrefsResponse, RequestError> {
        use crate::models::{ClientPrefs, NewClientPrefs};
        use crate::schema::clients::columns::uuid as client_uuid;
        use crate::schema::clients::table as clients;
        use crate::schema::prefs::table as prefs;

        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_reader.get().unwrap();
        let client: models::Client = clients.filter(client_uuid.eq(request_uuid)).first(&conn)?;
        let client_prefs: ClientPrefs = match ClientPrefs::belonging_to(&client).first(&conn) {
            Ok(client_prefs) => client_prefs,
            Err(_) => {
                let conn = self.db_writer.get().unwrap();
                diesel::insert_into(prefs)
                    .values(&NewClientPrefs {
                        client_id: client.id,
                    })
                    .get_result(&conn)?
            }
        };

        Ok(proto::GetPrefsResponse {
            client_id: request.client_id.clone(),
            prefs: Some(client_prefs.into()),
        })
    }

    // Get all the clients referred by a client
    #[instrument(INFO)]
    fn handle_get_referrals(
        &self,
        request: &proto::GetReferralsRequest,
    ) -> Result<proto::GetReferralsResponse, RequestError> {
        use crate::schema::clients::columns::referred_by;
        use crate::schema::clients::table as clients;

        let request_uuid = uuid::Uuid::parse_str(&request.referred_by_client_id)?;

        let conn = self.db_reader.get().unwrap();
        let referred_clients = clients
            .filter(referred_by.eq(request_uuid))
            .load::<models::Client>(&conn)?;

        Ok(proto::GetReferralsResponse {
            referred_by_client_id: request.referred_by_client_id.clone(),
            referrals: referred_clients.iter().map(proto::Client::from).collect(),
        })
    }

    // Updates the underlying client model
    #[instrument(INFO)]
    fn handle_update_prefs(
        &self,
        request: &proto::UpdatePrefsRequest,
    ) -> Result<proto::UpdatePrefsResponse, RequestError> {
        use crate::models::{ClientPrefs, UpdateClientPrefs};
        use crate::schema::clients::columns::uuid as client_uuid;
        use crate::schema::clients::table as clients;

        let request_uuid = uuid::Uuid::parse_str(&request.client_id)?;

        let conn = self.db_reader.get().unwrap();
        let client: models::Client = clients.filter(client_uuid.eq(request_uuid)).first(&conn)?;

        let conn = self.db_writer.get().unwrap();

        let updated_prefs: UpdateClientPrefs = match request.prefs.as_ref() {
            Some(prefs) => prefs.into(),
            _ => UpdateClientPrefs {
                email_notifications: EmailNotificationsPref::Ral,
                include_in_leaderboard: true,
            },
        };

        let client_prefs: ClientPrefs = diesel::update(ClientPrefs::belonging_to(&client))
            .set(&updated_prefs)
            .get_result(&conn)?;

        Ok(proto::UpdatePrefsResponse {
            client_id: request.client_id.clone(),
            prefs: Some(client_prefs.into()),
        })
    }

    // Get client stats
    #[instrument(INFO)]
    fn handle_get_stats(
        &self,
        _request: &proto::GetStatsRequest,
    ) -> Result<proto::GetStatsResponse, RequestError> {
        use chrono::Datelike;
        use diesel::prelude::*;
        use diesel::result::Error;
        use diesel::sql_query;

        let conn = self.db_reader.get().unwrap();
        let result: Result<Vec<AmountByDateQueryResult>, Error> = sql_query(
            r#"
                SELECT Count(1) AS count,
                    dq.date  AS ds
                FROM   (SELECT ( CURRENT_DATE - offs ) AS date
                        FROM   Generate_series(1, 31, 1) AS offs) AS dq
                    LEFT OUTER JOIN clients c
                                    ON Date(c.created_at) <= dq.date
                GROUP  BY dq.date
                ORDER  BY dq.date
            "#,
        )
        .get_results(&conn);

        let clients_by_date = match result {
            Ok(result) => result
                .iter()
                .map(|result| proto::CountByDate {
                    count: result.count,
                    year: result.ds.year(),
                    month: result.ds.month() as i32,
                    day: result.ds.day() as i32,
                })
                .collect(),
            Err(err) => {
                error!("Error reading stats: {:?}", err);
                vec![]
            }
        };

        let result: Result<Vec<AmountByClientQueryResult>, Error> = sql_query(
            r#"
                SELECT          CAST(c.ral * 100 AS BIGINT) AS amount_cents,
                                c.uuid      AS client_id
                FROM            clients     AS c
                LEFT OUTER JOIN prefs p
                ON              p.client_id = c.id
                WHERE           p.include_in_leaderboard = true
                ORDER BY        c.ral DESC limit 10
            "#,
        )
        .get_results(&conn);

        let clients_by_ral = match result {
            Ok(result) => result
                .iter()
                .map(|result| proto::AmountByClient {
                    amount_cents: result.amount_cents,
                    client_id: result.client_id.to_simple().to_string(),
                })
                .collect(),
            Err(err) => {
                error!("Error reading stats: {:?}", err);
                vec![]
            }
        };

        Ok(proto::GetStatsResponse {
            clients_by_date,
            clients_by_ral,
        })
    }
}

impl proto::server::Rolodex for Rolodex {
    type AuthHandshakeFuture = future::FutureResult<
        Response<proto::AuthHandshakeResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn auth_handshake(
        &mut self,
        request: Request<proto::AuthHandshakeRequest>,
    ) -> Self::AuthHandshakeFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_auth_handshake(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type AuthVerifyFuture =
        future::FutureResult<Response<proto::AuthVerifyResponse>, rolodex_grpc::tower_grpc::Status>;
    fn auth_verify(
        &mut self,
        request: Request<proto::AuthVerifyRequest>,
    ) -> Self::AuthVerifyFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_auth_verify(request.get_ref())
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

    type GetClientEmailFuture = future::FutureResult<
        Response<proto::GetClientEmailResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn get_client_email(
        &mut self,
        request: Request<proto::GetClientEmailRequest>,
    ) -> Self::GetClientEmailFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_get_client_email(request.get_ref())
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

    type UpdateClientRalFuture = future::FutureResult<
        Response<proto::UpdateClientResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn update_client_ral(
        &mut self,
        request: Request<proto::UpdateClientRalRequest>,
    ) -> Self::UpdateClientRalFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_update_client_ral(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type IncrementClientAvatarFuture = future::FutureResult<
        Response<proto::UpdateClientResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn increment_client_avatar(
        &mut self,
        request: Request<proto::IncrementClientAvatarRequest>,
    ) -> Self::IncrementClientAvatarFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_increment_client_avatar(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type UpdateClientPasswordFuture = future::FutureResult<
        Response<proto::UpdateClientResponse>,
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
        Response<proto::UpdateClientResponse>,
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
        Response<proto::UpdateClientResponse>,
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

    type VerifyPhoneFuture = future::FutureResult<
        Response<proto::VerifyPhoneResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn verify_phone(
        &mut self,
        request: Request<proto::VerifyPhoneRequest>,
    ) -> Self::VerifyPhoneFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_verify_phone(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type SendVerificationCodeFuture = future::FutureResult<
        Response<proto::SendVerificationCodeResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn send_verification_code(
        &mut self,
        request: Request<proto::SendVerificationCodeRequest>,
    ) -> Self::SendVerificationCodeFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_send_verification_code(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type GetPrefsFuture =
        future::FutureResult<Response<proto::GetPrefsResponse>, rolodex_grpc::tower_grpc::Status>;
    fn get_prefs(&mut self, request: Request<proto::GetPrefsRequest>) -> Self::GetPrefsFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_get_prefs(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type UpdatePrefsFuture = future::FutureResult<
        Response<proto::UpdatePrefsResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn update_prefs(
        &mut self,
        request: Request<proto::UpdatePrefsRequest>,
    ) -> Self::UpdatePrefsFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_update_prefs(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type GetReferralsFuture = future::FutureResult<
        Response<proto::GetReferralsResponse>,
        rolodex_grpc::tower_grpc::Status,
    >;
    fn get_referrals(
        &mut self,
        request: Request<proto::GetReferralsRequest>,
    ) -> Self::GetReferralsFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_get_referrals(request.get_ref())
            .map(Response::new)
            .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))
            .into_future()
    }

    type GetStatsFuture =
        future::FutureResult<Response<proto::GetStatsResponse>, rolodex_grpc::tower_grpc::Status>;
    fn get_stats(&mut self, request: Request<proto::GetStatsRequest>) -> Self::GetStatsFuture {
        use futures::future::IntoFuture;
        use rolodex_grpc::tower_grpc::{Code, Status};
        self.handle_get_stats(request.get_ref())
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
    use sha2::Sha256;
    use srp::client::SrpClient;
    use srp::groups::G_2048;
    use std::sync::Mutex;

    lazy_static! {
        static ref LOCK: Mutex<i32> = Mutex::new(0);
    }

    fn get_pools() -> (
        diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        r2d2_redis_cluster::r2d2::Pool<r2d2_redis_cluster::RedisClusterConnectionManager>,
    ) {
        let pg_manager = ConnectionManager::<PgConnection>::new(
            "postgres://postgres:password@127.0.0.1:5432/rolodex",
        );
        let db_pool = Pool::builder().build(pg_manager).unwrap();

        let redis_manager =
            r2d2_redis_cluster::RedisClusterConnectionManager::new("redis://127.0.0.1/").unwrap();
        let redis_pool = r2d2_redis_cluster::r2d2::Pool::builder()
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
                    diesel::delete(schema::$x::table).execute(&conn).unwrap();
                    assert_eq!(Ok(0), schema::$x::table.select(count(schema::$x::id)).first(&conn));
                )*
            };
        }

        empty_tables![client_account_actions, unique_email_addresses, clients];
    }

    fn email_in_table(
        db_pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        email: &str,
    ) -> bool {
        let conn = db_pool.get().unwrap();

        let count: i64 = schema::unique_email_addresses::table
            .select(count(schema::unique_email_addresses::id))
            .filter(schema::unique_email_addresses::email_as_entered.eq(email))
            .first(&conn)
            .unwrap();
        count > 0
    }

    fn phone_number_in_table(
        db_pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        phone_number: &str,
    ) -> bool {
        let conn = db_pool.get().unwrap();

        let count: i64 = schema::clients::table
            .select(count(schema::clients::id))
            .filter(schema::clients::phone_number.eq(phone_number))
            .first(&conn)
            .unwrap();
        count > 0
    }

    fn gen_salt() -> Vec<u8> {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        salt.to_vec()
    }

    fn gen_a() -> Vec<u8> {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut a = [0u8; 64];
        OsRng.fill_bytes(&mut a);
        a.to_vec()
    }

    fn make_srp_client<'a>(
        email: &str,
        password: &str,
        salt: &[u8],
        a: &[u8],
    ) -> (SrpClient<'a, Sha256>, Vec<u8>) {
        use srp::client::srp_private_key;
        let private_key = srp_private_key::<Sha256>(email.as_bytes(), password.as_bytes(), salt);
        (SrpClient::<Sha256>::new(&a, &G_2048), private_key.to_vec())
    }

    fn make_client(
        rolodex: &Rolodex,
        db_pool: &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        email: &str,
        password: &str,
    ) -> proto::NewClientResponse {
        let password_salt = gen_salt();
        let a = gen_a();
        let (srp_client, srp_private_key) = make_srp_client(email, password, &password_salt, &a);
        let password_verifier = srp_client.get_password_verifier(&srp_private_key);

        let result = rolodex.handle_add_client(&proto::NewClientRequest {
            full_name: "Bob Marley".into(),
            email: email.into(),
            phone_number: Some(proto::PhoneNumber {
                country_code: "US".into(),
                national_number: "4013213952".into(),
            }),
            password_verifier: password_verifier.clone(),
            password_salt: password_salt.clone(),
            box_public_key: "herp derp".into(),
            signing_public_key: "herp derp".into(),
            location: Some(proto::Location {
                ip_address: "127.0.0.1".into(),
                region: "United States".into(),
                region_subdivision: "New York".into(),
                city: "New York".into(),
            }),
        });
        assert_eq!(result.is_ok(), true);
        assert_eq!(email_in_table(&db_pool, email), true);

        let client = result.unwrap();

        assert_eq!(auth_client(rolodex, email, password, &client), true);

        client
    }

    fn auth_client(
        rolodex: &Rolodex,
        email: &str,
        password: &str,
        client: &proto::NewClientResponse,
    ) -> bool {
        let email = email.to_string();
        let a = gen_a();
        let srp_client = SrpClient::<Sha256>::new(&a, &G_2048);

        let auth_result = rolodex.handle_auth_handshake(&proto::AuthHandshakeRequest {
            email: email.clone(),
            a_pub: srp_client.get_a_pub().clone(),
            location: Some(proto::Location {
                ip_address: "127.0.0.1".into(),
                region: "United States".into(),
                region_subdivision: "New York".into(),
                city: "New York".into(),
            }),
        });
        assert_eq!(auth_result.is_ok(), true);
        let auth_result = auth_result.unwrap();
        assert_eq!(auth_result.email, email);

        let (srp_client, srp_private_key) =
            make_srp_client(&email, password, &auth_result.salt, &a);
        let a_pub = srp_client.get_a_pub().clone();
        let srp_client2 = srp_client
            .process_reply(&srp_private_key, &auth_result.b_pub)
            .unwrap();

        let auth_result = rolodex.handle_auth_verify(&proto::AuthVerifyRequest {
            email: email.clone(),
            a_pub,
            client_proof: srp_client2.get_proof().to_vec(),
            location: Some(proto::Location {
                ip_address: "127.0.0.1".into(),
                region: "United States".into(),
                region_subdivision: "New York".into(),
                city: "New York".into(),
            }),
        });
        assert_eq!(auth_result.is_ok(), true);
        let auth_result = auth_result.unwrap();
        assert_eq!(auth_result.client_id, client.client_id);

        let verify_result = srp_client2.verify_server(&auth_result.server_proof);
        assert_eq!(verify_result.is_ok(), true);

        verify_result.is_ok()
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

            let _client = make_client(&rolodex, &db_pool, "bob@aol.com", "secrit");

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

            let auth_result = rolodex.handle_auth_handshake(&proto::AuthHandshakeRequest {
                email: "lyle@aol.com".to_string(),
                a_pub: b"blah".to_vec(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
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

            let _client = make_client(&rolodex, &db_pool, "bob@aol.com", "secrit");

            let email = "bob@aol.com".to_string();
            let password_salt = gen_salt();
            let a = gen_a();
            let (srp_client, srp_private_key) =
                make_srp_client(&email, "secrit", &password_salt, &a);
            let password_verifier = srp_client.get_password_verifier(&srp_private_key);

            let result = rolodex.handle_add_client(&proto::NewClientRequest {
                full_name: "Bob Marley".into(),
                email: email.clone(),
                phone_number: Some(proto::PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213953".into(),
                }),
                password_verifier: password_verifier.clone(),
                password_salt: password_salt.clone(),
                box_public_key: "herp derp".into(),
                signing_public_key: "herp derp".into(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), false);

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

            let _client = make_client(&rolodex, &db_pool, "bob@aol.com", "secrit");

            let email = "bob2@aol.com".to_string();
            let password_salt = gen_salt();
            let a = gen_a();
            let (srp_client, srp_private_key) =
                make_srp_client(&email, "secrit", &password_salt, &a);
            let password_verifier = srp_client.get_password_verifier(&srp_private_key);

            let result = rolodex.handle_add_client(&proto::NewClientRequest {
                full_name: "Bob Marley".into(),
                email: email.clone(),
                phone_number: Some(proto::PhoneNumber {
                    country_code: "US".into(),
                    national_number: "4013213952".into(),
                }),
                password_verifier: password_verifier.clone(),
                password_salt: password_salt.clone(),
                box_public_key: "herp derp".into(),
                signing_public_key: "herp derp".into(),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });
            assert_eq!(result.is_ok(), false);
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

            let client = make_client(&rolodex, &db_pool, "bob@aol.com", "secrit");

            let get_client = rolodex.handle_get_client(&proto::GetClientRequest {
                id: Some(rolodex_grpc::proto::get_client_request::Id::ClientId(
                    client.client_id.clone(),
                )),
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
    fn test_add_client_update_client() {
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

            let client = make_client(&rolodex, &db_pool, "bob@aol.com", "secrit");

            // Update client model
            let update_result = rolodex.handle_update_client(&proto::UpdateClientRequest {
                client: Some(proto::Client {
                    client_id: client.client_id.to_string(),
                    full_name: "bob nob".into(),
                    box_public_key: "herp derp".into(),
                    signing_public_key: "herp derp".into(),
                    handle: "handle".into(),
                    profile: "profile".into(),
                }),
                location: Some(proto::Location {
                    ip_address: "127.0.0.1".into(),
                    region: "United States".into(),
                    region_subdivision: "New York".into(),
                    city: "New York".into(),
                }),
            });

            if update_result.is_err() {
                panic!("err: {:?}", update_result.err());
            }
            assert_eq!(update_result.is_ok(), true);
            assert_eq!(update_result.unwrap().result, proto::Result::Success as i32);

            let updated_client = rolodex
                .handle_get_client(&proto::GetClientRequest {
                    calling_client_id: client.client_id.clone(),
                    id: Some(rolodex_grpc::proto::get_client_request::Id::ClientId(
                        client.client_id.clone(),
                    )),
                })
                .unwrap();

            let updated_client = updated_client.client.unwrap().clone();
            assert_eq!(updated_client.full_name, "bob nob");
            assert_eq!(updated_client.box_public_key, "herp derp");
            assert_eq!(updated_client.signing_public_key, "herp derp");
            assert_eq!(updated_client.handle, "handle");
            assert_eq!(updated_client.profile, "profile");

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

            let email = "bob@aol.com";

            let client = make_client(&rolodex, &db_pool, email, "secrit");

            // Update password
            let new_password = "new_password";
            let password_salt = gen_salt();
            let a = gen_a();
            let (srp_client, srp_private_key) =
                make_srp_client(email, new_password, &password_salt, &a);
            let password_verifier = srp_client.get_password_verifier(&srp_private_key);

            let update_result =
                rolodex.handle_update_client_password(&proto::UpdateClientPasswordRequest {
                    client_id: client.client_id.to_string(),
                    password_verifier,
                    password_salt,
                    location: None,
                });

            if update_result.is_err() {
                panic!("err: {:?}", update_result.err());
            }
            assert_eq!(update_result.is_ok(), true);
            assert_eq!(update_result.unwrap().result, proto::Result::Success as i32);

            // Try auth with new password
            assert_eq!(auth_client(&rolodex, email, new_password, &client), true);

            future::ok(())
        }));
    }

    #[test]
    fn test_add_client_update_email() {
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

            let client = make_client(&rolodex, &db_pool, "bob@aol.com", "secrit");

            // Update Email
            let update_result =
                rolodex.handle_update_client_email(&proto::UpdateClientEmailRequest {
                    client_id: client.client_id.to_string(),
                    email: "hello@yahoo.com".into(),
                    location: Some(proto::Location {
                        ip_address: "127.0.0.1".into(),
                        region: "United States".into(),
                        region_subdivision: "New York".into(),
                        city: "New York".into(),
                    }),
                });

            if update_result.is_err() {
                panic!("err: {:?}", update_result.err());
            }
            assert_eq!(update_result.is_ok(), true);
            assert_eq!(update_result.unwrap().result, proto::Result::Success as i32);

            assert_eq!(email_in_table(&db_pool, "hello@yahoo.com"), true);

            future::ok(())
        }));
    }

    #[test]
    fn test_add_client_update_phone_number() {
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

            let client = make_client(&rolodex, &db_pool, "bob@aol.com", "secrit");

            // Update phone number
            let update_result =
                rolodex.handle_update_client_phone_number(&proto::UpdateClientPhoneNumberRequest {
                    client_id: client.client_id.to_string(),
                    phone_number: Some(proto::PhoneNumber {
                        country_code: "US".into(),
                        national_number: "5105825858".into(),
                    }),
                    location: Some(proto::Location {
                        ip_address: "127.0.0.1".into(),
                        region: "United States".into(),
                        region_subdivision: "New York".into(),
                        city: "New York".into(),
                    }),
                });

            if update_result.is_err() {
                panic!("err: {:?}", update_result.err());
            }
            assert_eq!(update_result.is_ok(), true);
            assert_eq!(update_result.unwrap().result, proto::Result::Success as i32);
            assert_eq!(phone_number_in_table(&db_pool, "+1 510-582-5858"), true);

            future::ok(())
        }));
    }
}
