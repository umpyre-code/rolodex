use regex::Regex;

pub fn handle(value: &str) -> String {
    let value = value.to_lowercase();
    let re = Regex::new(r"[^a-z0-9_.-]").unwrap();
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

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_handle_sanitizer() {
        assert_eq!(handle("bob 🐶 lol"), "boblol");
        assert_eq!(handle("    bob 🐶 lol"), "boblol");

        let long_string = (0..10000).map(|_| "X").collect::<String>();
        assert_eq!(handle(&long_string).len(), 100);
    }

    #[test]
    fn test_profile_sanitizer() {
        assert_eq!(profile("bob 🐶 lol"), "bob 🐶 lol");

        let long_string = (0..10000).map(|_| "X").collect::<String>();
        assert_eq!(profile(&long_string).len(), 1000);
    }

    #[test]
    fn test_full_name_sanitizer() {
        assert_eq!(full_name("bob 🐶 lol"), "bob 🐶 lol");

        let long_string = (0..10000).map(|_| "X").collect::<String>();
        assert_eq!(full_name(&long_string).len(), 100);
    }
}
