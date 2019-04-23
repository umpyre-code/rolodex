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

#[instrument(INFO)]
fn handle_authenticate(_request: &AuthRequest) -> AuthResponse {
    AuthResponse {
        result: auth_response::Result::Failure as i32,
    }
}

#[instrument(INFO)]
fn handle_add_user(_request: &NewUserRequest) -> NewUserResponse {
    NewUserResponse {
            result: Some(new_user_response::Result::UserId("derp".to_string())),
        }
}

impl<DBPool> server::Rolodex for Rolodex<DBPool>
where
    DBPool: std::clone::Clone,
{
    type AuthenticateFuture = future::FutureResult<Response<AuthResponse>, tower_grpc::Status>;
    type AddUserFuture = future::FutureResult<Response<NewUserResponse>, tower_grpc::Status>;

    fn authenticate(&mut self, request: Request<AuthRequest>) -> Self::AuthenticateFuture {
        info!("REQUEST = {:?}", request);

        let response = Response::new(handle_authenticate(request.get_ref()));

        future::ok(response)
    }

    fn add_user(&mut self, request: Request<NewUserRequest>) -> Self::AddUserFuture {
        info!("REQUEST = {:?}", request);

        let response = Response::new(handle_add_user(request.get_ref()));

        future::ok(response)
    }
}
