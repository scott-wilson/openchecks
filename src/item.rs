pub trait Item:
    std::cmp::PartialEq + std::cmp::PartialOrd + std::fmt::Display + std::fmt::Debug
{
    type Value;

    fn value(&self) -> Self::Value;
    fn type_hint(&self) -> Option<&'static str> {
        None
    }
}
