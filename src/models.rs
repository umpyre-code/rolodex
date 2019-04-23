use crate::schema::users;
use chrono::NaiveDateTime;
use uuid::Uuid;

#[derive(Queryable)]
pub struct User {
  pub id: i32,
  pub uuid: Uuid,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
  pub full_name: String,
}

#[derive(AsChangeset, Insertable)]
#[table_name = "users"]
pub struct NewUser {
  pub full_name: String,
  pub password_hash: String,
}

#[derive(Queryable)]
pub struct UniqueEmailAddress {
  pub id: i32,
  pub user_id: i32,
  pub created_at: NaiveDateTime,
  pub updated_at: NaiveDateTime,
  pub email_as_entered: String,
  pub email_without_labels: String,
}

#[derive(AsChangeset, Insertable)]
#[table_name = "unique_email_addresses"]
pub struct NewUniqueEmailAddress {
  pub user_id: i32,
  pub email_as_entered: String,
  pub email_without_labels: String,
}
