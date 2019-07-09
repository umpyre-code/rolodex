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
    pub email: String,
    pub phone_number: String,
    pub box_public_key: String,
    pub sign_public_key: String,
}

#[derive(Queryable, Insertable)]
#[table_name = "clients"]
pub struct NewClient {
    pub full_name: String,
    pub phone_number: String,
    pub box_public_key: String,
    pub sign_public_key: String,
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
