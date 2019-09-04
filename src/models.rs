extern crate uuid;

use crate::schema::*;
use crate::sql_types::*;
use chrono::NaiveDateTime;

/// This represents the private (internal) client model
#[derive(Queryable, Identifiable)]
pub struct Client {
    pub id: i64,
    pub uuid: uuid::Uuid,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub full_name: String,
    pub password_verifier: Vec<u8>,
    pub password_salt: Vec<u8>,
    pub phone_number: String,
    pub box_public_key: String,
    pub signing_public_key: String,
    pub profile: Option<String>,
    pub handle: Option<String>,
    pub handle_lowercase: Option<String>,
    pub phone_sms_verified: bool,
    pub ral: i32,
    pub avatar_version: i32,
}

#[derive(Insertable)]
#[table_name = "clients"]
pub struct NewClient {
    pub full_name: String,
    pub password_verifier: Vec<u8>,
    pub password_salt: Vec<u8>,
    pub phone_number: String,
    pub box_public_key: String,
    pub signing_public_key: String,
}

// Struct used for client auth flow
#[derive(Queryable)]
pub struct ClientAuth {
    pub id: i64,
    pub uuid: uuid::Uuid,
    pub password_verifier: Vec<u8>,
    pub password_salt: Vec<u8>,
}

#[derive(AsChangeset, Debug)]
#[table_name = "clients"]
#[changeset_options(treat_none_as_null = "true")]
pub struct UpdateClient {
    pub full_name: String,
    pub box_public_key: String,
    pub signing_public_key: String,
    pub profile: Option<String>,
    pub handle: Option<String>,
    pub handle_lowercase: Option<String>,
    pub ral: i32,
    pub avatar_version: i32,
}

#[derive(Queryable, Associations, Identifiable)]
#[table_name = "unique_email_addresses"]
#[belongs_to(Client)]
pub struct UniqueEmailAddress {
    pub id: i64,
    pub client_id: i64,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub email_as_entered: String,
    pub email_without_labels: String,
}

/// This represents all internal client email addresses
#[derive(AsChangeset, Insertable, Associations)]
#[table_name = "unique_email_addresses"]
#[belongs_to(Client)]
pub struct NewUniqueEmailAddress {
    pub client_id: i64,
    pub email_as_entered: String,
    pub email_without_labels: String,
}

#[derive(AsChangeset, Insertable, Associations)]
#[table_name = "client_account_actions"]
#[belongs_to(Client)]
pub struct NewClientAccountAction {
    pub client_id: i64,
    pub action: ClientAccountAction,
    pub ip_address: Option<String>,
    pub region: Option<String>,
    pub region_subdivision: Option<String>,
    pub city: Option<String>,
}

#[derive(AsChangeset, Insertable, Associations)]
#[table_name = "phone_verification_codes"]
#[belongs_to(Client)]
pub struct NewPhoneVerificationCode {
    pub client_id: i64,
    pub code: i32,
}

#[derive(Queryable, Associations, Identifiable)]
#[table_name = "phone_verification_codes"]
#[belongs_to(Client)]
pub struct PhoneVerificationCode {
    pub id: i64,
    pub client_id: i64,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub code: i32,
}
