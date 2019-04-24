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
    db_pool: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
    redis_pool: r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
}

#[derive(Debug, Fail)]
enum RequestError {
    #[fail(display = "invalid phone number: {}", phone_number)]
    InvalidPhoneNumber { phone_number: String },
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
        db_pool: diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>,
        redis_pool: r2d2_redis::r2d2::Pool<r2d2_redis::RedisConnectionManager>,
    ) -> Self {
        Rolodex {
            db_pool,
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

        let new_user = NewUser {
            full_name: request.full_name.clone(),
            password_hash: request.password_hash.clone(),
            phone_number: request.phone_number.clone(),
        };

        let email: Email = request.email.to_lowercase().parse()?;
        let redis_conn = self.redis_pool.get()?;
        email.check_validity(&*redis_conn)?;

        let email_as_entered = email.email_as_entered.clone();
        let email_without_labels = email.email_without_labels.clone();

        let conn = self.db_pool.get().unwrap();
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

        Ok(user.uuid.to_string())
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
