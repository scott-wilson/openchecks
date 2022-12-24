use std::borrow::Cow;

bitflags::bitflags! {
    pub struct CheckHint: u8 {
        const NONE = 0b0;
        const AUTO_FIX = 0b1;
    }
}

pub trait CheckMetadata {
    fn title(&self) -> Cow<str>;

    fn description(&self) -> Cow<str>;

    fn hint(&self) -> CheckHint {
        CheckHint::all()
    }
}

pub trait Check: CheckMetadata {
    type Item: crate::Item;
    type Items: std::iter::IntoIterator<Item = Self::Item>;

    fn check(&self) -> crate::CheckResult<Self::Item, Self::Items>;

    fn auto_fix(&mut self) -> Result<(), crate::Error> {
        Err(crate::Error::new("Auto fix is not implemented."))
    }
}

#[async_trait::async_trait]
pub trait AsyncCheck: CheckMetadata {
    type Item: crate::Item;
    type Items: std::iter::IntoIterator<Item = Self::Item>;

    async fn async_check(&self) -> crate::CheckResult<Self::Item, Self::Items>;

    async fn async_auto_fix(&mut self) -> Result<(), crate::Error> {
        Err(crate::Error::new("Auto fix is not implemented."))
    }
}
