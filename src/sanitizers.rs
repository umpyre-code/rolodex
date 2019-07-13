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

pub trait Optional
where
    Self: std::marker::Sized,
{
    fn into_option(&self) -> Option<Self>;
}

impl Optional for String where
    Self: std::marker::Sized, {
     fn into_option(&self) -> Option<Self> {
        if self.is_empty() {
            None
        } else {
            Some(self.clone())
        }
    }
}
