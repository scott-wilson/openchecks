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

/// The check metadata.
///
/// This stores the information about the check that is either useful for humans
/// (the [title](CheckMetadata::title) and
/// [description](CheckMetadata::description)) or useful for systems that uses
/// the check ([hint](CheckMetadata::hint)). For example, a user interface could
/// use the title and description to render information for an artist to inform
/// them about what the check will validate and how it will fix issues (if
/// supported). The hint then could be used to render other useful information
/// such as whether the check supports automatic fixes in general, whether it
/// could be overridden by a supervisor, etc.
///
/// This is one of the two traits (this and the [Check] or [AsyncCheck]) that
/// must be implemented for the check system to run.
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
///
/// This is responsible for validating the input data and returning a result
/// such as pass or fail. It can also provide extra data such as what caused the
/// status (for example, the scene nodes that are named incorrectly).
///
/// If the check supports it, then the data being validated can be automatically
/// fixed.
///
/// # Examples
///
/// ## Simple Check
///
/// ```rust
/// # use openchecks::{CheckResult, Item, Check, CheckMetadata, Status, run};
/// #
/// # #[derive(Debug, PartialEq, PartialOrd)]
/// # struct IntItem(i32);
/// #
/// # impl std::fmt::Display for IntItem {
/// #     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
/// #         self.0.fmt(f)
/// #     }
/// # }
/// #
/// # impl Item for IntItem {
/// #     type Value<'a>
/// #             = i32
/// #         where
/// #             Self: 'a;
/// #
/// #     fn value(&self) -> Self::Value<'_> {
/// #         self.0
/// #     }
/// # }
/// #
/// struct IsEqualCheck(i32);
///
/// impl CheckMetadata for IsEqualCheck {
///     fn title(&self) -> std::borrow::Cow<str> {
///         "Is Equal Check".into()
///     }
///
///     fn description(&self) -> std::borrow::Cow<str> {
///         "Check if the number is equal.".into()
///     }
/// }
///
/// impl Check for IsEqualCheck {
///     type Item = IntItem;
///
///     type Items = Vec<IntItem>;
///
///     fn check(&self) -> CheckResult<Self::Item, Self::Items> {
///         if self.0 % 2 == 0 {
///             CheckResult::new_passed("The number is even.", None, false, false)
///         } else {
///             CheckResult::new_failed("The number is not even.", None, false, false)
///         }
///     }
/// }
///
/// impl IsEqualCheck {
///     pub fn new(value: i32) -> Self{
///         Self(value)
///     }
/// }
///
/// let check = IsEqualCheck::new(2);
/// let result = run(&check);
///
/// assert_eq!(*result.status(), Status::Passed);
/// ```
///
/// ## Check with Automatic Fix
///
/// ```rust
/// # use openchecks::{CheckResult, Item, Check, CheckMetadata, Status, Error, auto_fix, run};
/// #
/// # #[derive(Debug, PartialEq, PartialOrd)]
/// # struct IntItem(i32);
/// #
/// # impl std::fmt::Display for IntItem {
/// #     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
/// #         self.0.fmt(f)
/// #     }
/// # }
/// #
/// # impl Item for IntItem {
/// #     type Value<'a>
/// #             = i32
/// #         where
/// #             Self: 'a;
/// #
/// #     fn value(&self) -> Self::Value<'_> {
/// #         self.0
/// #     }
/// # }
/// #
/// struct IsZeroCheck(i32);
///
/// impl CheckMetadata for IsZeroCheck {
///     fn title(&self) -> std::borrow::Cow<str> {
///         "Is Zero Check".into()
///     }
///
///     fn description(&self) -> std::borrow::Cow<str> {
///         "Check if the number is zero.".into()
///     }
/// }
///
/// impl Check for IsZeroCheck {
///     type Item = IntItem;
///
///     type Items = Vec<IntItem>;
///
///     fn check(&self) -> CheckResult<Self::Item, Self::Items> {
///         if self.0 == 0 {
///             CheckResult::new_passed("Good", None, true, false)
///         } else {
///             CheckResult::new_failed("Bad", None, true, false)
///         }
///     }
///
///     fn auto_fix(&mut self) -> Result<(), Error> {
///         self.0 = 0;
///         Ok(())
///     }
/// }
///
/// impl IsZeroCheck {
///     pub fn new(value: i32) -> Self{
///         Self(value)
///     }
/// }
///
/// let mut check = IsZeroCheck::new(1);
/// let result = run(&check);
///
/// assert_eq!(*result.status(), Status::Failed);
///
/// if result.can_fix() {
///     let result = auto_fix(&mut check);
///     assert_eq!(*result.status(), Status::Passed);
/// }
///
/// ```
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
    ///
    /// # Errors
    ///
    /// Will return an error if the `auto_fix` is not implemented, or an error
    /// happened in the `auto_fix`, such as a filesystem error.
    fn auto_fix(&mut self) -> Result<(), crate::Error> {
        Err(crate::Error::new("Auto fix is not implemented."))
    }
}

/// The check trait, but supporting async.
///
/// This is responsible for validating the input data and returning a result
/// such as pass or fail. It can also provide extra data such as what caused the
/// status (for example, the scene nodes that are named incorrectly).
///
/// If the check supports it, then the data being validated can be automatically
/// fixed.
///
/// # Examples
///
/// ## Simple Check
///
/// ```rust
/// # use openchecks::{CheckResult, Item, AsyncCheck, CheckMetadata, Status, async_run};
/// #
/// # #[derive(Debug, PartialEq, PartialOrd)]
/// # struct IntItem(i32);
/// #
/// # impl std::fmt::Display for IntItem {
/// #     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
/// #         self.0.fmt(f)
/// #     }
/// # }
/// #
/// # impl Item for IntItem {
/// #     type Value<'a>
/// #             = i32
/// #         where
/// #             Self: 'a;
/// #
/// #     fn value(&self) -> Self::Value<'_> {
/// #         self.0
/// #     }
/// # }
/// #
/// struct IsEqualCheck(i32);
///
/// impl CheckMetadata for IsEqualCheck {
///     fn title(&self) -> std::borrow::Cow<str> {
///         "Is Equal Check".into()
///     }
///
///     fn description(&self) -> std::borrow::Cow<str> {
///         "Check if the number is equal.".into()
///     }
/// }
///
/// #[async_trait::async_trait]
/// impl AsyncCheck for IsEqualCheck {
///     type Item = IntItem;
///
///     type Items = Vec<IntItem>;
///
///     async fn async_check(&self) -> CheckResult<Self::Item, Self::Items> {
///         if self.0 % 2 == 0 {
///             CheckResult::new_passed("The number is even.", None, false, false)
///         } else {
///             CheckResult::new_failed("The number is not even.", None, false, false)
///         }
///     }
/// }
///
/// impl IsEqualCheck {
///     pub fn new(value: i32) -> Self{
///         Self(value)
///     }
/// }
///
/// # #[tokio::main]
/// # async fn main() {
/// let check = IsEqualCheck::new(2);
/// let result = async_run(&check).await;
///
/// assert_eq!(*result.status(), Status::Passed);
/// # }
/// ```
///
/// ## Check with Automatic Fix
///
/// ```rust
/// # use openchecks::{CheckResult, Item, AsyncCheck, CheckMetadata, Status, Error, async_auto_fix, async_run};
/// #
/// # #[derive(Debug, PartialEq, PartialOrd)]
/// # struct IntItem(i32);
/// #
/// # impl std::fmt::Display for IntItem {
/// #     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
/// #         self.0.fmt(f)
/// #     }
/// # }
/// #
/// # impl Item for IntItem {
/// #     type Value<'a>
/// #             = i32
/// #         where
/// #             Self: 'a;
/// #
/// #     fn value(&self) -> Self::Value<'_> {
/// #         self.0
/// #     }
/// # }
/// #
/// struct IsZeroCheck(i32);
///
/// impl CheckMetadata for IsZeroCheck {
///     fn title(&self) -> std::borrow::Cow<str> {
///         "Is Zero Check".into()
///     }
///
///     fn description(&self) -> std::borrow::Cow<str> {
///         "Check if the number is zero.".into()
///     }
/// }
///
/// #[async_trait::async_trait]
/// impl AsyncCheck for IsZeroCheck {
///     type Item = IntItem;
///
///     type Items = Vec<IntItem>;
///
///     async fn async_check(&self) -> CheckResult<Self::Item, Self::Items> {
///         if self.0 == 0 {
///             CheckResult::new_passed("Good", None, true, false)
///         } else {
///             CheckResult::new_failed("Bad", None, true, false)
///         }
///     }
///
///     async fn async_auto_fix(&mut self) -> Result<(), Error> {
///         self.0 = 0;
///         Ok(())
///     }
/// }
///
/// impl IsZeroCheck {
///     pub fn new(value: i32) -> Self{
///         Self(value)
///     }
/// }
///
/// # #[tokio::main]
/// # async fn main() {
/// let mut check = IsZeroCheck::new(1);
/// let result = async_run(&check).await;
///
/// assert_eq!(*result.status(), Status::Failed);
///
/// if result.can_fix() {
///     let result = async_auto_fix(&mut check).await;
///     assert_eq!(*result.status(), Status::Passed);
/// }
/// # }
/// ```
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
    ///
    /// # Errors
    ///
    /// Will return an error if the `auto_fix` is not implemented, or an error
    /// happened in the `auto_fix`, such as a filesystem error.
    async fn async_auto_fix(&mut self) -> Result<(), crate::Error> {
        Err(crate::Error::new("Auto fix is not implemented."))
    }
}
