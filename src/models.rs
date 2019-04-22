use crate::schema::users;
use chrono::NaiveDateTime;
use uuid::Uuid;

#[derive(Queryable)]
pub struct User {
    pub id: i32,
    pub uuid: Uuid,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub name: String,
}

#[derive(AsChangeset, Insertable)]
#[table_name = "users"]
pub struct NewUser {
    pub name: String,
}
