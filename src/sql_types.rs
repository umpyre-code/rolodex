use std::io::Write;

use diesel::deserialize::{self, FromSql};
use diesel::expression::{Expression};
use diesel::pg::Pg;
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::Text;

#[derive(Debug, PartialEq, DbEnum)]
#[PgType = "account_action"]
#[DieselType = "Account_action"]
pub enum ClientAccountAction {
    #[db_rename = "created"]
    Created,
    #[db_rename = "deleted"]
    Deleted,
    #[db_rename = "password updated"]
    PasswordUpdated,
    #[db_rename = "public key updated"]
    PublicKeyUpdated,
    #[db_rename = "phone number updated"]
    PhoneNumberUpdated,
    #[db_rename = "email updated"]
    EmailUpdated,
    #[db_rename = "updated"]
    Updated,
    #[db_rename = "authenticated"]
    Authenticated,
}

pub type Citext = Text;
