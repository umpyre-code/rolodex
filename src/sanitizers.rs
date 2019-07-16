use regex::Regex;

pub fn handle(value: &str) -> String {
    let value = value.to_string();
    let value = value.to_lowercase();
    let re = Regex::new(r"[a-z0-9_.-]").unwrap();
    let mut value = re.replace_all(&value, "").to_string();
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
