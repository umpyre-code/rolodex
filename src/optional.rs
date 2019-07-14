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
