table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    client_account_actions (id) {
        id -> Int8,
        client_id -> Int8,
        created_at -> Timestamp,
        action -> Nullable<Account_action>,
        ip_address -> Nullable<Text>,
        region -> Nullable<Text>,
        region_subdivision -> Nullable<Text>,
        city -> Nullable<Text>,
    }
}

table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    clients (id) {
        id -> Int8,
        uuid -> Uuid,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        full_name -> Text,
        password_verifier -> Bytea,
        password_salt -> Bytea,
        phone_number -> Text,
        box_public_key -> Text,
        signing_public_key -> Text,
        profile -> Nullable<Text>,
        handle -> Nullable<Text>,
        handle_lowercase -> Nullable<Text>,
        phone_sms_verified -> Bool,
        ral -> Int4,
    }
}

table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    phone_verification_codes (id) {
        id -> Int8,
        client_id -> Int8,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        code -> Int4,
    }
}

table! {
    use diesel::sql_types::*;
    use crate::sql_types::*;

    unique_email_addresses (id) {
        id -> Int8,
        client_id -> Int8,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        email_as_entered -> Text,
        email_without_labels -> Text,
    }
}

joinable!(client_account_actions -> clients (client_id));
joinable!(phone_verification_codes -> clients (client_id));
joinable!(unique_email_addresses -> clients (client_id));

allow_tables_to_appear_in_same_query!(
    client_account_actions,
    clients,
    phone_verification_codes,
    unique_email_addresses,
);
