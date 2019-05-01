extern crate uuid;

use crate::schema::unique_email_addresses;
use crate::schema::users;
use chrono::NaiveDateTime;

/// This represents the private (internal) user model
#[derive(Queryable, Identifiable)]
pub struct User {
    pub id: i64,
    pub uuid: uuid::Uuid,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub full_name: String,
    pub email: String,
    pub phone_number: String,
}

#[derive(Queryable, Associations, Identifiable)]
#[table_name = "unique_email_addresses"]
#[belongs_to(User)]
pub struct UniqueEmailAddress {
    pub id: i64,
    pub user_id: i64,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub email_as_entered: String,
    pub email_without_labels: String,
}

/// This represents all internal user email addresses
#[derive(AsChangeset, Insertable, Associations)]
#[table_name = "unique_email_addresses"]
#[belongs_to(User)]
pub struct NewUniqueEmailAddress {
    pub user_id: i64,
    pub email_as_entered: String,
    pub email_without_labels: String,
}
