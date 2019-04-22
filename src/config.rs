use log::info;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use toml;
use yansi::Paint;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub service: Service,
    pub database: Database,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    pub worker_threads: usize,
    pub ca_cert_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub bind_to_addr: String,
}

#[derive(Debug, Deserialize)]
pub struct Database {
    pub hostname: String,
    pub port: i32,
    pub username: String,
    pub password: String,
    pub connection_pool_size: u32,
}

fn get_rolodex_toml_path() -> String {
    env::var("ROLODEX_TOML").unwrap_or_else(|_| "Rolodex.toml".to_string())
}

lazy_static! {
    pub static ref CONFIG: Config = {
        let rolodex_toml_path = get_rolodex_toml_path();
        let config: Config = toml::from_str(&read_file_to_string(&rolodex_toml_path)).unwrap();
        config
    };
}

fn read_file_to_string(filename: &str) -> String {
    let mut file = File::open(filename).expect("Unable to open the file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Unable to read the file");
    contents
}

pub fn load_config() {
    info!(
        "Loaded Rolodex configuration values from {}",
        get_rolodex_toml_path()
    );
    info!("CONFIG => {:#?}", Paint::red(&*CONFIG));
}
