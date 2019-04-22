table! {
    unique_email_addresses (id) {
        id -> Int4,
        user_id -> Nullable<Int4>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
        email_as_entered -> Nullable<Varchar>,
        email_without_labels -> Nullable<Varchar>,
    }
}

table! {
    users (id) {
        id -> Int4,
        uuid -> Nullable<Uuid>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
        full_name -> Nullable<Varchar>,
        password_hash -> Nullable<Varchar>,
    }
}

joinable!(unique_email_addresses -> users (user_id));

allow_tables_to_appear_in_same_query!(unique_email_addresses, users,);
