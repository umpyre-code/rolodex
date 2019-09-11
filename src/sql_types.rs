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
    #[db_rename = "phone verified"]
    PhoneVerified,
}

#[derive(Debug, PartialEq, DbEnum)]
#[PgType = "email_notifications_pref"]
#[DieselType = "Email_notifications_pref"]
pub enum EmailNotificationsPref {
    #[db_rename = "never"]
    Never,
    #[db_rename = "ral"]
    Ral,
    #[db_rename = "always"]
    Always,
}
