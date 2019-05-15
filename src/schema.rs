table! {
    clients (id) {
        id -> Int8,
        uuid -> Uuid,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        full_name -> Text,
        password_hash -> Text,
        phone_number -> Text,
        public_key -> Text,
        region -> Nullable<Text>,
        region_subdivision -> Nullable<Text>,
        city -> Nullable<Text>,
    }
}

table! {
    unique_email_addresses (id) {
        id -> Int8,
        client_id -> Int8,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        email_as_entered -> Text,
        email_without_labels -> Text,
    }
}

joinable!(unique_email_addresses -> clients (client_id));

allow_tables_to_appear_in_same_query!(
    clients,
    unique_email_addresses,
);
