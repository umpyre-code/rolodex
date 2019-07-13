pub fn handle(value: &str) -> String {
    let mut value = value.trim().to_string();
    value.truncate(100);
    value
}

pub fn full_name(value: &str) -> String {
    let mut value = value.trim().to_string();
    value.truncate(100);
    value
}

pub fn public_key(value: &str) -> String {
    let mut value = value.trim().to_string();
    value.truncate(1000);
    value
}

pub fn profile(value: &str) -> String {
    let mut value = value.trim().to_string();
    value.truncate(1000);
    value
}
