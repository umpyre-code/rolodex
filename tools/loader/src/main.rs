extern crate redis;
extern crate reqwest;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate url;
#[macro_use]
extern crate failure;

use redis::Commands;
use redis::PipelineCommands;
use url::Url;

#[derive(Debug, Fail)]
enum Error {
    #[fail(display = "Url parser error: {}", err)]
    UrlParse { err: String },
    #[fail(display = "request failed: {}", err)]
    Reqwest { err: String },
    #[fail(display = "redis error: {}", err)]
    Redis { err: String },
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

    let con = redis_client.get_connection()?;
    let mut pipe = redis::pipe();
    pipe.atomic().del("public_suffix_list");
    public_suffix_list.iter().for_each(|domain| {
        pipe.sadd("public_suffix_list", domain);
    });
    pipe.execute(&con);

    let member_count: usize = con.scard("public_suffix_list").unwrap();
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
    let banned_domains_url = Url::parse("https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf")?;
    info!("Fetching banned domains list from {}", banned_domains_url);

    let banned_domains_list =
        parse_banned_domains_list(reqwest_client.get(banned_domains_url).send()?.text()?);
    info!("Read {} domains", banned_domains_list.len());

    let con = redis_client.get_connection()?;
    let mut pipe = redis::pipe();
    pipe.atomic().del("banned_email_domains");
    banned_domains_list.iter().for_each(|domain| {
        pipe.sadd("banned_email_domains", domain);
    });
    pipe.execute(&con);

    let member_count: usize = con.scard("banned_email_domains").unwrap();
    info!("Read {} members out of redis set", member_count);
    assert_eq!(banned_domains_list.len(), member_count);

    Ok(())
}

fn main() -> Result<(), Error> {
    env_logger::init();

    info!("Starting up");

    let reqwest_client = reqwest::Client::new();
    let redis_client = redis::Client::open("redis://127.0.0.1/")?;

    update_public_suffix_list(&reqwest_client, &redis_client)?;
    update_banned_domains_list(&reqwest_client, &redis_client)?;

    Ok(())
}
