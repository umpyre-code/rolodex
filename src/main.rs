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
extern crate color_backtrace;
extern crate instrumented;
extern crate phonenumber;
extern crate r2d2_redis;
extern crate regex;
extern crate rolodex_grpc;
extern crate tokio_rustls;
extern crate toml;
extern crate trust_dns;
extern crate url;
extern crate yansi;

mod config;
mod email;
mod models;
mod password_hash;
mod schema;
mod service;

use futures::{Future, Stream};
use r2d2_redis::RedisConnectionManager;
use rolodex_grpc::proto::server;
use std::fs::File;
use std::io::BufReader;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{
    AllowAnyAuthenticatedClient, Certificate, PrivateKey, RootCertStore, ServerConfig,
};
use tokio_rustls::TlsAcceptor;
use tower_hyper::server::{Http, Server};

fn load_certs(path: &str) -> Vec<Certificate> {
    certs(&mut BufReader::new(
        File::open(path).expect("Couldn't open file"),
    ))
    .expect("Unable to load certs")
}

fn load_keys(path: &str) -> Vec<PrivateKey> {
    rsa_private_keys(&mut BufReader::new(
        File::open(path).expect("Couldn't open file"),
    ))
    .expect("Unable to read private keys")
}

fn get_tls_config() -> TlsAcceptor {
    // TLS config
    // load root CA
    let mut root_cert_store = RootCertStore::empty();
    load_certs(&config::CONFIG.service.ca_cert_path)
        .iter()
        .for_each(|cert| {
            root_cert_store.add(cert).expect("Unable to load root CA");
        });
    let mut tls_config = ServerConfig::new(AllowAnyAuthenticatedClient::new(root_cert_store));
    // load server certs
    tls_config
        .set_single_cert(
            load_certs(&config::CONFIG.service.tls_cert_path),
            load_keys(&config::CONFIG.service.tls_key_path).remove(0),
        )
        .expect("invalid key or certificate");
    TlsAcceptor::from(Arc::new(tls_config))
}

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

fn get_redis_pool(redis: &config::Redis) -> r2d2_redis::r2d2::Pool<RedisConnectionManager> {
    let manager = RedisConnectionManager::new(&format!("redis://{}/", redis.address)[..]).unwrap();
    let pool = r2d2_redis::r2d2::Pool::builder()
        .build(manager)
        .expect("Unable to create redis connection pool");

    let conn = pool.get();
    assert!(conn.is_ok());

    pool
}

pub fn main() {
    use std::env;

    color_backtrace::install();

    ::env_logger::init();

    config::load_config();

    // Allow disablement of metrics reporting for testing
    if env::var_os("DISABLE_INSTRUMENTED").is_none() {
        instrumented::init(&config::CONFIG.metrics.bind_to_address);
    }

    let new_service = server::RolodexServer::new(service::Rolodex::new(
        get_db_pool(&config::CONFIG.database.reader),
        get_db_pool(&config::CONFIG.database.writer),
        get_redis_pool(&config::CONFIG.redis.reader),
        get_redis_pool(&config::CONFIG.redis.writer),
    ));

    let server = Arc::new(Mutex::new(Server::new(new_service)));

    let http = Http::new().http2_only(true).clone();

    let tls_config = get_tls_config();

    let addr = config::CONFIG.service.bind_to_address.parse().unwrap();
    let bind = TcpListener::bind(&addr).expect("bind");

    let serve = bind
        .incoming()
        .for_each(move |tls_sock| {
            let http = http.clone();
            let server = server.clone();
            let addr = tls_sock.peer_addr().ok();
            if let Err(e) = tls_sock.set_nodelay(true) {
                return Err(e);
            }
            info!("New connection from addr={:?}", addr);
            let done = tls_config
                .accept(tls_sock)
                .and_then(move |sock| {
                    let serve = server.lock().unwrap().serve_with(sock, http.clone());
                    tokio::spawn(serve.map_err(|e| error!("hyper error: {:?}", e)));

                    Ok(())
                })
                .map_err(move |err| error!("TLS error: {:?} - {:?}", err, addr));
            tokio::spawn(done);

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
