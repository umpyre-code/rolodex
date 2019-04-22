use futures::future;
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

impl<DBPool> server::Rolodex for Rolodex<DBPool>
where
    DBPool: std::clone::Clone,
{
    type AuthenticateFuture = future::FutureResult<Response<AuthResponse>, tower_grpc::Status>;
    type AddUserFuture = future::FutureResult<Response<NewUserResponse>, tower_grpc::Status>;

    fn authenticate(&mut self, request: Request<AuthRequest>) -> Self::AuthenticateFuture {
        info!("REQUEST = {:?}", request);

        let response = Response::new(AuthResponse {
            result: auth_response::Result::Failure as i32,
            auth_token: "lol".to_string(),
        });

        future::ok(response)
    }

    fn add_user(&mut self, request: Request<NewUserRequest>) -> Self::AddUserFuture {
        info!("REQUEST = {:?}", request);

        let response = Response::new(NewUserResponse {
            result: Some(new_user_response::Result::UserId("derp".to_string())),
        });

        future::ok(response)
    }
}
