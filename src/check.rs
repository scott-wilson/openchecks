use std::borrow::Cow;

bitflags::bitflags! {
    /// The check hint flags contains useful information such as whether the
    /// check should support auto-fixing issues.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct CheckHint: u8 {
        /// The check supports no extra features.
        ///
        /// This should be considered the most conservative check *feature*. For
        /// example, no auto-fix, check cannot be skipped before running, etc.
        const NONE = 0b0;
        /// The check supports auto-fixing.
        ///
        /// This does not guarantee that the auto-fix is implemented, but
        /// instead that the auto-fix should be implemented.
        const AUTO_FIX = 0b1;
    }
}

/// The base check.
pub trait CheckMetadata {
    /// The human readable title for the check.
    ///
    /// User interfaces should use the title for displaying the check.
    fn title(&self) -> Cow<str>;

    /// The human readable description for the check.
    ///
    /// This should include information about what the check is looking for,
    /// what are the conditions for the different statuses it supports, and if
    /// there's an auto-fix, what the auto-fix will do.
    fn description(&self) -> Cow<str>;

    /// The hint gives information about what features the check supports.
    fn hint(&self) -> CheckHint {
        CheckHint::all()
    }
}

/// The check trait.
pub trait Check: CheckMetadata {
    /// The item type is a wrapper around the object(s) that caused the result.
    type Item: crate::Item;

    /// The items are an iterable of objects that caused the result.
    type Items: std::iter::IntoIterator<Item = Self::Item>;

    /// Run a validation on the input data and output the result of the
    /// validation.
    fn check(&self) -> crate::CheckResult<Self::Item, Self::Items>;

    /// Automatically fix the issue detected by the [check](crate::Check::check)
    /// method.
    fn auto_fix(&mut self) -> Result<(), crate::Error> {
        Err(crate::Error::new("Auto fix is not implemented."))
    }
}

/// The check trait, but supporting async.
#[async_trait::async_trait]
pub trait AsyncCheck: CheckMetadata {
    /// The item type is a wrapper around the object(s) that caused the result.
    type Item: crate::Item;

    /// The items are an iterable of objects that caused the result.
    type Items: std::iter::IntoIterator<Item = Self::Item>;

    /// Run a validation on the input data and output the result of the
    /// validation.
    async fn async_check(&self) -> crate::CheckResult<Self::Item, Self::Items>;

    /// Automatically fix the issue detected by the
    /// [check](crate::AsyncCheck::async_check) method.
    async fn async_auto_fix(&mut self) -> Result<(), crate::Error> {
        Err(crate::Error::new("Auto fix is not implemented."))
    }
}
