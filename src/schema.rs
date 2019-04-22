table! {
    users (id) {
        id -> Int4,
        uuid -> Uuid,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        name -> Nullable<Varchar>,
    }
}
