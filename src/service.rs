use futures::future;
use instrumented::instrument;
use rolodex_grpc::proto::{
    auth_response, new_user_response, server, AuthRequest, AuthResponse, NewUserRequest,
    NewUserResponse,
};
use tower_grpc::{Request, Response};

#[derive(Clone, Debug)]
pub struct Rolodex<DBPool> {
    db_pool: DBPool,
}

impl<T> Rolodex<T> {
    pub fn new(db_pool: T) -> Self {
        Rolodex { db_pool }
    }
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
        }
    }
}

/// Returns the user_id for this user if auth succeeds
#[instrument(INFO)]
fn handle_authenticate(_request: &AuthRequest) -> Result<String, RequestError> {
    Ok("handle_authenticate".to_string())
}

/// Returns the user_id for this user if account creation succeeded
#[instrument(INFO)]
fn handle_add_user(_request: &NewUserRequest) -> Result<String, RequestError> {
    Ok("handle_add_user".to_string())
}

impl<DBPool> server::Rolodex for Rolodex<DBPool>
where
    DBPool: std::clone::Clone,
{
    type AuthenticateFuture = future::FutureResult<Response<AuthResponse>, tower_grpc::Status>;
    type AddUserFuture = future::FutureResult<Response<NewUserResponse>, tower_grpc::Status>;

    fn authenticate(&mut self, request: Request<AuthRequest>) -> Self::AuthenticateFuture {
        let response = Response::new(
            handle_authenticate(request.get_ref())
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
            handle_add_user(request.get_ref())
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
