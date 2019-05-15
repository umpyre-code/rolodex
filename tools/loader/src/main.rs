extern crate data_encoding;
extern crate redis;
extern crate reqwest;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate url;
#[macro_use]
extern crate failure;
extern crate sodiumoxide;

use redis::Commands;
use redis::PipelineCommands;
use url::Url;

fn b2b_hash(s: &str, digest_size: usize) -> String {
    use data_encoding::BASE64_NOPAD;
    use sodiumoxide::crypto::generichash;
    let mut hasher = generichash::State::new(digest_size, None).unwrap();
    hasher.update(s.as_bytes()).unwrap();
    let digest = hasher.finalize().unwrap();
    BASE64_NOPAD.encode(digest.as_ref())
}

#[derive(Debug, Fail)]
enum Error {
    #[fail(display = "Url parser error: {}", err)]
    UrlParse { err: String },
    #[fail(display = "request failed: {}", err)]
    Reqwest { err: String },
    #[fail(display = "redis error: {}", err)]
    Redis { err: String },
    #[fail(display = "bad arguments")]
    BadArgs,
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error::UrlParse {
            err: format!("{}", err),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::Reqwest {
            err: format!("{}", err),
        }
    }
}

impl From<redis::RedisError> for Error {
    fn from(err: redis::RedisError) -> Error {
        Error::Redis {
            err: format!("{}", err),
        }
    }
}

fn add_slick_to_set(
    redis_client: &redis::Client,
    key: &str,
    slice: &[String],
) -> Result<usize, Error> {
    let con = redis_client.get_connection()?;
    redis::transaction(&con, &[key], |pipe| {
        pipe.del(key);
        slice.iter().for_each(|item| {
            pipe.sadd(key, item);
        });
        pipe.query(&con)
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
    redis_client: &redis::Client,
) -> Result<(), Error> {
    let public_suffix_url = Url::parse("https://publicsuffix.org/list/public_suffix_list.dat")?;

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
    redis_client: &redis::Client,
) -> Result<(), Error> {
    let banned_domains_url = Url::parse("https://raw.githubclientcontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf")?;
    info!("Fetching banned domains list from {}", banned_domains_url);

    let banned_domains_list =
        parse_banned_domains_list(reqwest_client.get(banned_domains_url).send()?.text()?);
    info!("Read {} domains", banned_domains_list.len());

    let member_count =
        add_slick_to_set(redis_client, "banned_email_domains", &banned_domains_list)?;

    info!("Read {} members out of redis set", member_count);
    assert_eq!(banned_domains_list.len(), member_count);

    Ok(())
}

fn parse_banned_passwords_list(list: String) -> Vec<String> {
    list.lines()
        .map(str::trim) // trim leading/trailing whitespace
        .filter(|s| !s.is_empty()) // remove empty lines
        .map(|s| {
            b2b_hash(s, 64)
        })
        .collect()
}

fn update_banned_password_hashes_list(
    reqwest_client: &reqwest::Client,
    redis_client: &redis::Client,
) -> Result<(), Error> {
    let banned_passwords_url = Url::parse("https://raw.githubclientcontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt")?;
    info!(
        "Fetching banned passwords list from {}",
        banned_passwords_url
    );

    let banned_password_hashes_list =
        parse_banned_passwords_list(reqwest_client.get(banned_passwords_url).send()?.text()?);
    info!("Read {} passwords", banned_password_hashes_list.len());

    let member_count = add_slick_to_set(
        redis_client,
        "banned_password_hashes",
        &banned_password_hashes_list,
    )?;

    info!("Read {} members out of redis set", member_count);
    assert_eq!(banned_password_hashes_list.len(), member_count);

    Ok(())
}

fn main() -> Result<(), Error> {
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
    let redis_client = redis::Client::open(&format!("redis://{}/", args[1])[..])?;

    update_public_suffix_list(&reqwest_client, &redis_client)?;
    update_banned_domains_list(&reqwest_client, &redis_client)?;
    update_banned_password_hashes_list(&reqwest_client, &redis_client)?;

    Ok(())
}
