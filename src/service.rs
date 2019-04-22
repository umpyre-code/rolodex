use futures::future;
use rolodex_grpc::proto::{auth_result, server, AuthRequest, AuthResult, NewUser, User};
use tower_grpc::{Request, Response};

#[derive(Clone, Debug)]
pub struct Rolodex;

impl server::Rolodex for Rolodex {
    type AuthenticateFuture = future::FutureResult<Response<AuthResult>, tower_grpc::Status>;
    type AddUserFuture = future::FutureResult<Response<User>, tower_grpc::Status>;

    fn authenticate(&mut self, request: Request<AuthRequest>) -> Self::AuthenticateFuture {
        info!("REQUEST = {:?}", request);

        let response = Response::new(AuthResult {
            result: auth_result::Result::Failure as i32,
            auth_token: "lol".to_string(),
        });

        future::ok(response)
    }

    fn add_user(&mut self, request: Request<NewUser>) -> Self::AddUserFuture {
        info!("REQUEST = {:?}", request);

        let response = Response::new(User {
            user_id: "lol".to_string(),
            name: "lol".to_string(),
        });

        future::ok(response)
    }
}
