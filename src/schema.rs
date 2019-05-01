table! {
    unique_email_addresses (id) {
        id -> Int8,
        user_id -> Int8,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        email_as_entered -> Text,
        email_without_labels -> Text,
    }
}

table! {
    users (id) {
        id -> Int8,
        uuid -> Uuid,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        full_name -> Text,
        password_hash -> Text,
        phone_number -> Text,
    }
}

joinable!(unique_email_addresses -> users (user_id));

allow_tables_to_appear_in_same_query!(unique_email_addresses, users,);
