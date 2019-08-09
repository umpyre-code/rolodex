extern crate data_encoding;
extern crate redis_cluster_rs;
extern crate reqwest;
#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate failure;

use redis_cluster_rs::{Commands, PipelineCommands};

#[derive(Debug, Fail)]
enum Error {
    #[fail(display = "request failed: {}", err)]
    Reqwest { err: String },
    #[fail(display = "redis error: {}", err)]
    Redis { err: String },
    #[fail(display = "bad arguments")]
    BadArgs,
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::Reqwest {
            err: format!("{}", err),
        }
    }
}

impl From<redis_cluster_rs::redis::RedisError> for Error {
    fn from(err: redis_cluster_rs::redis::RedisError) -> Error {
        Error::Redis {
            err: format!("{}", err),
        }
    }
}

fn add_slick_to_set(
    redis_client: &redis_cluster_rs::Client,
    key: &str,
    slice: &[String],
) -> Result<usize, Error> {
    let mut con = redis_client.get_connection()?;
    redis_cluster_rs::redis::transaction(&mut con, &[key], |con, pipe| {
        pipe.del(key);
        slice.iter().for_each(|item| {
            pipe.sadd(key, item);
        });
        pipe.query(con)
    })?;
    let member_count: usize = con.scard(key)?;

    Ok(member_count)
}

fn parse_public_suffix_list(list: String) -> Vec<String> {
    list.lines()
        .map(str::trim) // trim leading/trailing whitespace
        .filter(|s| !s.is_empty()) // remove empty lines
        .filter(|s| !s.starts_with("//")) // drop comments
        .filter(|s| !s.starts_with("*.")) // skip wildcards
        .map(std::string::ToString::to_string)
        .collect()
}

fn update_public_suffix_list(
    reqwest_client: &reqwest::Client,
    redis_client: &redis_cluster_rs::Client,
) -> Result<(), Error> {
    let public_suffix_url = "https://publicsuffix.org/list/public_suffix_list.dat";

    info!("Fetching public suffix list from {}", public_suffix_url);
    let public_suffix_list =
        parse_public_suffix_list(reqwest_client.get(public_suffix_url).send()?.text()?);
    info!("Read {} domains", public_suffix_list.len());

    let member_count = add_slick_to_set(redis_client, "public_suffix_list", &public_suffix_list)?;

    info!("Read {} members out of redis set", member_count);
    assert_eq!(public_suffix_list.len(), member_count);

    Ok(())
}

fn parse_banned_domains_list(list: String) -> Vec<String> {
    list.lines()
        .map(str::trim) // trim leading/trailing whitespace
        .filter(|s| !s.is_empty()) // remove empty lines
        .map(std::string::ToString::to_string)
        .collect()
}

fn update_banned_domains_list(
    reqwest_client: &reqwest::Client,
    redis_client: &redis_cluster_rs::Client,
) -> Result<(), Error> {
    let banned_domains_url = "https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf";
    info!("Fetching banned domains list from {}", banned_domains_url);

    let mut banned_domains_list =
        parse_banned_domains_list(reqwest_client.get(banned_domains_url).send()?.text()?);

    // Disallow Apple's email forwarding service
    banned_domains_list.push("privaterelay.appleid.com".to_string());

    info!("Read {} domains", banned_domains_list.len());

    let member_count =
        add_slick_to_set(redis_client, "banned_email_domains", &banned_domains_list)?;

    info!("Read {} members out of redis set", member_count);
    assert_eq!(banned_domains_list.len(), member_count);

    Ok(())
}

fn main() -> Result<(), Error> {
    use redis_cluster_rs::redis::IntoConnectionInfo;
    use std::env;

    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        error!("Usage: loader <redis addr>");
        return Err(Error::BadArgs);
    }

    info!("Starting up");
    info!("args: {:?}", args);

    let reqwest_client = reqwest::Client::new();

    let redis_client = redis_cluster_rs::Client::open(
        vec![format!("redis://{}", args[1])]
            .iter()
            .map(|c| c.into_connection_info().unwrap())
            .collect(),
    )?;

    update_public_suffix_list(&reqwest_client, &redis_client)?;
    update_banned_domains_list(&reqwest_client, &redis_client)?;

    Ok(())
}
