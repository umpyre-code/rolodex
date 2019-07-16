pub trait Optional
where
    Self: std::marker::Sized,
{
    fn into_option(&self) -> Option<Self>;
}

impl Optional for String
where
    Self: std::marker::Sized,
{
    fn into_option(&self) -> Option<Self> {
        if self.is_empty() {
            None
        } else {
            Some(self.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_optional() {
        assert_eq!(String::from("lol").into_option(), Some(String::from("lol")));
        assert_eq!(String::from("").into_option(), None);
    }
}
