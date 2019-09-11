extern crate tokio_rustls;

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use tokio_rustls::rustls::internal::pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{
    AllowAnyAuthenticatedClient, Certificate, PrivateKey, RootCertStore, ServerConfig,
};

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
