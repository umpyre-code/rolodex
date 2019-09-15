#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;

extern crate env_logger;
extern crate rolodex;
extern crate uuid;

use rolodex::config;
use rolodex::db;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Url parser error: {}", err)]
    UrlParse { err: String },
    #[fail(display = "IO error: {}", err)]
    IoError { err: String },
    #[fail(display = "bad arguments")]
    BadArgs,
    #[fail(display = "client is not serving")]
    NotServing,
    #[fail(display = "bad response")]
    BadResponse,
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error::UrlParse {
            err: format!("{}", err),
        }
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(err: http::uri::InvalidUri) -> Error {
        Error::UrlParse {
            err: format!("{}", err),
        }
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Error {
        Error::IoError {
            err: format!("{}", err),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IoError {
            err: format!("{}", err),
        }
    }
}

struct ElasticSearchClient {
    client: reqwest::Client,
}

impl ElasticSearchClient {
    fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
    fn delete(&self, client_id: &str) {
        self.client
            .delete(&format!(
                "{}/client_profiles/{}",
                config::CONFIG.elasticsearch.url,
                client_id
            ))
            .send()
            .expect("unabled to delete doc from elasticsearch");
    }
}

fn cleanup_unverified(
    db: &rolodex::diesel::r2d2::Pool<
        rolodex::diesel::r2d2::ConnectionManager<rolodex::diesel::pg::PgConnection>,
    >,
) {
    use rolodex::chrono::prelude::*;
    use rolodex::chrono::Duration;
    use rolodex::diesel::delete;
    use rolodex::diesel::prelude::*;
    use rolodex::schema::clients::columns::{created_at, phone_sms_verified, uuid};
    use rolodex::schema::clients::table as clients;
    use uuid::Uuid;

    info!("checking for unverified accounts");

    let expiry_time = (Utc::now() - Duration::hours(1)).naive_utc();

    let conn = db.get().unwrap();

    let client_ids = conn
        .transaction::<Vec<Uuid>, diesel::result::Error, _>(|| {
            let filter = created_at.lt(expiry_time).and(phone_sms_verified.eq(false));

            let client_ids = clients.select(uuid).filter(filter).load::<Uuid>(&conn)?;

            delete(clients.filter(filter)).execute(&conn)?;

            Ok(client_ids)
        })
        .expect("transaction error");

    let es_client = ElasticSearchClient::new();

    client_ids
        .iter()
        .for_each(|client_id| es_client.delete(&client_id.to_simple().to_string()));

    info!("{} unverified accounts deleted", client_ids.len())
}

pub fn main() -> Result<(), Error> {
    env_logger::init();

    let db = db::get_db_pool(&config::CONFIG.database.writer);

    cleanup_unverified(&db);

    Ok(())
}
