#[macro_use]
extern crate diesel_derive_enum;
extern crate data_encoding;
extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio;
extern crate tower_hyper;
#[macro_use]
extern crate diesel;
extern crate chrono;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
extern crate instrumented;
extern crate phonenumber;
extern crate r2d2_redis_cluster;
extern crate rand;
extern crate regex;
extern crate rolodex_grpc;
extern crate sha3;
extern crate srp;
extern crate toml;
extern crate trust_dns;
extern crate url;
extern crate yansi;

mod config;
mod email;
mod models;
mod optional;
mod sanitizers;
mod schema;
mod service;
mod sql_types;

use futures::{Future, Stream};
use r2d2_redis_cluster::RedisClusterConnectionManager;
use rolodex_grpc::proto::server;
use tokio::net::TcpListener;
use tower_hyper::server::{Http, Server};

fn get_db_pool(
    database: &config::Database,
) -> diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>> {
    use diesel::pg::PgConnection;
    use diesel::r2d2::{ConnectionManager, Pool};

    let manager = ConnectionManager::<PgConnection>::new(format!(
        "postgres://{}:{}@{}:{}/{}",
        database.username, database.password, database.host, database.port, database.name,
    ));

    let db_pool = Pool::builder()
        .max_size(database.connection_pool_size)
        .build(manager)
        .expect("Unable to create DB connection pool");

    let conn = db_pool.get();
    assert!(conn.is_ok());

    db_pool
}

fn get_redis_pool(
    redis: &config::Redis,
    readonly: bool,
) -> r2d2_redis_cluster::r2d2::Pool<RedisClusterConnectionManager> {
    use r2d2_redis_cluster::redis_cluster_rs::redis::IntoConnectionInfo;
    let mut manager =
        RedisClusterConnectionManager::new(vec![redis.address.into_connection_info().unwrap()])
            .unwrap();
    manager.set_readonly(readonly);
    let pool = r2d2_redis_cluster::r2d2::Pool::builder()
        .build(manager)
        .expect("Unable to create redis connection pool");

    let conn = pool.get();
    assert!(conn.is_ok());

    pool
}

pub fn main() {
    use std::env;

    ::env_logger::init();

    config::load_config();

    // Allow disablement of metrics reporting for testing
    if env::var_os("DISABLE_INSTRUMENTED").is_none() {
        instrumented::init(&config::CONFIG.metrics.bind_to_address);
    }

    let new_service = server::RolodexServer::new(service::Rolodex::new(
        get_db_pool(&config::CONFIG.database.reader),
        get_db_pool(&config::CONFIG.database.writer),
        get_redis_pool(&config::CONFIG.redis, true),
        get_redis_pool(&config::CONFIG.redis, false),
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
