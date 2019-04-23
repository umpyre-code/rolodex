extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio;
extern crate tower_h2;
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
extern crate r2d2_postgres;
extern crate rolodex_grpc;
extern crate tokio_rustls;
extern crate toml;
extern crate tower_grpc;
extern crate yansi;

mod config;
mod schema;
mod service;

use futures::{Future, Stream};
use r2d2_postgres::postgres::NoTls;
use r2d2_postgres::PostgresConnectionManager;
use rolodex_grpc::proto::server;
use std::fs::File;
use std::io::BufReader;
use std::sync::{Arc, Mutex};
use tokio::executor::DefaultExecutor;
use tokio::net::TcpListener;
use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{
    AllowAnyAuthenticatedClient, Certificate, PrivateKey, RootCertStore, ServerConfig,
};
use tokio_rustls::TlsAcceptor;
use tower_h2::Server;

// use models::*;

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

fn get_db_pool() -> r2d2_postgres::r2d2::Pool<
    r2d2_postgres::PostgresConnectionManager<r2d2_postgres::postgres::NoTls>,
> {
    let manager = PostgresConnectionManager::new(
        format!(
            "host={} port={} user={} password={}",
            config::CONFIG.database.host,
            config::CONFIG.database.port,
            config::CONFIG.database.username,
            config::CONFIG.database.password,
        )
        .parse()
        .unwrap(),
        NoTls,
    );

    let db_pool = r2d2_postgres::r2d2::Pool::builder()
        .max_size(config::CONFIG.database.connection_pool_size)
        .build(manager)
        .expect("Unable to create DB connection pool");

    let mut client = db_pool.get().unwrap();
    client
        .execute("SELECT 1", &[])
        .expect("Unable to execute test query");

    db_pool
}

pub fn main() {
    color_backtrace::install();

    ::env_logger::init();

    config::load_config();

    instrumented::init(&config::CONFIG.metrics.bind_to_address);

    let new_service = server::RolodexServer::new(service::Rolodex::new(get_db_pool()));

    let h2_settings = Default::default();
    let h2 = Arc::new(Mutex::new(Server::new(
        new_service,
        h2_settings,
        DefaultExecutor::current(),
    )));

    let tls_config = get_tls_config();

    let addr = config::CONFIG.service.bind_to_addr.parse().unwrap();
    let bind = TcpListener::bind(&addr).expect("bind");

    let serve = bind
        .incoming()
        .for_each(move |tls_sock| {
            let addr = tls_sock.peer_addr().ok();
            if let Err(e) = tls_sock.set_nodelay(true) {
                return Err(e);
            }
            info!("New connection from addr={:?}", addr);
            let h2_inner = h2.clone();
            let done = tls_config
                .accept(tls_sock)
                .and_then(move |sock| {
                    let serve = h2_inner.lock().unwrap().serve(sock);
                    tokio::spawn(serve.map_err(|e| error!("h2 error: {:?}", e)));

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
