#[macro_use]
extern crate log;

extern crate env_logger;
extern crate rolodex;

use rolodex::config;
use rolodex::db;
use rolodex::futures::{Future, Stream};
use rolodex::instrumented;
use rolodex::rolodex_grpc::proto::server;
use rolodex::service;
use rolodex::tokio::net::TcpListener;
use rolodex::tower_hyper::server::{Http, Server};

pub fn main() {
    use std::env;

    env_logger::init();

    config::load_config();

    // Allow disablement of metrics reporting for testing
    if env::var_os("DISABLE_INSTRUMENTED").is_none() {
        instrumented::init(&config::CONFIG.metrics.bind_to_address);
    }

    let new_service = server::RolodexServer::new(service::Rolodex::new(
        db::get_db_pool(&config::CONFIG.database.reader),
        db::get_db_pool(&config::CONFIG.database.writer),
        db::get_redis_pool(&config::CONFIG.redis, true),
        db::get_redis_pool(&config::CONFIG.redis, false),
    ));

    let mut server = Server::new(new_service);

    let http = Http::new().http2_only(true).clone();

    let addr = config::CONFIG.service.bind_to_address.parse().unwrap();
    let bind = TcpListener::bind(&addr).expect("bind");

    let serve = bind
        .incoming()
        .for_each(move |sock| {
            let addr = sock.peer_addr().ok();
            info!("New connection from addr={:?}", addr);

            let serve = server.serve_with(sock, http.clone());
            tokio::spawn(serve.map_err(|e| error!("hyper error: {:?}", e)));

            Ok(())
        })
        .map_err(|e| error!("accept error: {}", e));

    let mut rt = tokio::runtime::Builder::new()
        .core_threads(config::CONFIG.service.worker_threads)
        .build()
        .expect("Unable to build tokio runtime");

    rt.spawn(serve);
    info!(
        "Started server with {} threads, listening on {}",
        config::CONFIG.service.worker_threads,
        addr
    );
    rt.shutdown_on_idle().wait().expect("Error in main loop");
}
