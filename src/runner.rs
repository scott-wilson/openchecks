/// Run a check.
///
/// Running a check should never fail, but instead return a failure check
/// result. The run function might return a
/// [Status::SystemError](crate::Status::SystemError) if the system runs into an
/// error that must be resolved by the team supporting and implementing the
/// checks.
///
/// However, if there is a panic, then this will not capture the panic, and
/// simply let the panic bubble up the stack since it assumes that the
/// environment is now in a bad and unrecoverable state.
///
/// # Examples
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
/// #     type Value = i32;
/// #
/// #     fn value(&self) -> Self::Value {
/// #         self.0
/// #     }
/// # }
/// #
/// # struct IsEqualCheck(i32);
/// #
/// # impl CheckMetadata for IsEqualCheck {
/// #     fn title(&self) -> std::borrow::Cow<str> {
/// #         todo!()
/// #     }
/// #
/// #     fn description(&self) -> std::borrow::Cow<str> {
/// #         todo!()
/// #     }
/// # }
/// #
/// # #[async_trait::async_trait]
/// # impl AsyncCheck for IsEqualCheck {
/// #     type Item = IntItem;
/// #
/// #     type Items = Vec<IntItem>;
/// #
/// #     async fn async_check(&self) -> CheckResult<Self::Item, Self::Items> {
/// #         if self.0 % 2 == 0 {
/// #             CheckResult::new_passed("Good", None, false, false)
/// #         } else {
/// #             CheckResult::new_failed("Bad", None, false, false)
/// #         }
/// #     }
/// # }
/// #
/// # impl IsEqualCheck {
/// #     pub fn new(value: i32) -> Self{
/// #         Self(value)
/// #     }
/// # }
/// #
/// # #[tokio::main]
/// # async fn main() {
/// let check = IsEqualCheck::new(2);
/// let result = async_run(&check).await;
///
/// assert_eq!(*result.status(), Status::Passed);
/// # }
/// ```
pub async fn async_run<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>>(
    check: &impl crate::AsyncCheck<Item = Item, Items = Items>,
) -> crate::CheckResult<Item, Items> {
    let now = std::time::Instant::now();

    let mut result = check.async_check().await;

    result.set_check_duration(now.elapsed());

    result
}

/// Automatically fix an issue found by a check.
///
/// This function should only be run after the [check runner](crate::async_run)
/// returns a result, and that result can be fixed. Otherwise, the fix might try
/// to fix an already "good" object, causing issues with the object.
///
/// The auto-fix will re-run the [check runner](crate::async_run) to validate
/// that it has actually fixed the issue.
///
/// This will return a result with the
/// [Status::SystemError](crate::Status::SystemError) status if the check does
/// not have the [CheckHint::AUTO_FIX](crate::CheckHint::AUTO_FIX) flag set, or
/// an auto-fix returned an error. In the case of the latter, it will include
/// the error with the check result.
///
/// # Examples
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
/// #     type Value = i32;
/// #
/// #     fn value(&self) -> Self::Value {
/// #         self.0
/// #     }
/// # }
/// #
/// # struct IsZeroCheck(i32);
/// #
/// # impl CheckMetadata for IsZeroCheck {
/// #     fn title(&self) -> std::borrow::Cow<str> {
/// #         todo!()
/// #     }
/// #
/// #     fn description(&self) -> std::borrow::Cow<str> {
/// #         todo!()
/// #     }
/// # }
/// #
/// # #[async_trait::async_trait]
/// # impl AsyncCheck for IsZeroCheck {
/// #     type Item = IntItem;
/// #
/// #     type Items = Vec<IntItem>;
/// #
/// #     async fn async_check(&self) -> CheckResult<Self::Item, Self::Items> {
/// #         if self.0 == 0 {
/// #             CheckResult::new_passed("Good", None, true, false)
/// #         } else {
/// #             CheckResult::new_failed("Bad", None, true, false)
/// #         }
/// #     }
/// #
/// #     async fn async_auto_fix(&mut self) -> Result<(), Error> {
/// #         self.0 = 0;
/// #         Ok(())
/// #     }
/// # }
/// #
/// # impl IsZeroCheck {
/// #     pub fn new(value: i32) -> Self{
/// #         Self(value)
/// #     }
/// # }
/// #
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
pub async fn async_auto_fix<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>>(
    check: &mut (impl crate::AsyncCheck<Item = Item, Items = Items> + Send),
) -> crate::CheckResult<Item, Items> {
    let now = std::time::Instant::now();

    if !check.hint().contains(crate::CheckHint::AUTO_FIX) {
        let mut result = crate::CheckResult::new(
            crate::Status::SystemError,
            "Check does not implement auto fix.",
            None,
            false,
            false,
            None,
        );
        result.set_fix_duration(now.elapsed());

        return result;
    }

    if let Err(err) = check.async_auto_fix().await {
        let mut result = crate::CheckResult::new(
            crate::Status::SystemError,
            "Error in auto fix.",
            None,
            false,
            false,
            Some(err),
        );
        result.set_fix_duration(now.elapsed());

        return result;
    }

    let fix_duration = now.elapsed();
    let mut result = async_run(check).await;
    result.set_fix_duration(fix_duration);

    result
}

/// Run a check.
///
/// Running a check should never fail, but instead return a failure check
/// result. The run function might return a
/// [Status::SystemError](crate::Status::SystemError) if the system runs into an
/// error that must be resolved by the team supporting and implementing the
/// checks.
///
/// However, if there is a panic, then this will not capture the panic, and
/// simply let the panic bubble up the stack since it assumes that the
/// environment is now in a bad and unrecoverable state.
///
/// # Examples
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
/// #     type Value = i32;
/// #
/// #     fn value(&self) -> Self::Value {
/// #         self.0
/// #     }
/// # }
/// #
/// # struct IsEqualCheck(i32);
/// #
/// # impl CheckMetadata for IsEqualCheck {
/// #     fn title(&self) -> std::borrow::Cow<str> {
/// #         todo!()
/// #     }
/// #
/// #     fn description(&self) -> std::borrow::Cow<str> {
/// #         todo!()
/// #     }
/// # }
/// #
/// # impl Check for IsEqualCheck {
/// #     type Item = IntItem;
/// #
/// #     type Items = Vec<IntItem>;
/// #
/// #     fn check(&self) -> CheckResult<Self::Item, Self::Items> {
/// #         if self.0 % 2 == 0 {
/// #             CheckResult::new_passed("Good", None, false, false)
/// #         } else {
/// #             CheckResult::new_failed("Bad", None, false, false)
/// #         }
/// #     }
/// # }
/// #
/// # impl IsEqualCheck {
/// #     pub fn new(value: i32) -> Self{
/// #         Self(value)
/// #     }
/// # }
/// #
/// let check = IsEqualCheck::new(2);
/// let result = run(&check);
///
/// assert_eq!(*result.status(), Status::Passed);
/// ```
pub fn run<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>>(
    check: &impl crate::Check<Item = Item, Items = Items>,
) -> crate::CheckResult<Item, Items> {
    let now = std::time::Instant::now();

    let mut result = check.check();

    result.set_check_duration(now.elapsed());

    result
}

/// Automatically fix an issue found by a check.
///
/// This function should only be run after the [check runner](crate::run)
/// returns a result, and that result can be fixed. Otherwise, the fix might try
/// to fix an already "good" object, causing issues with the object.
///
/// The auto-fix will re-run the [check runner](crate::run) to validate that it
/// has actually fixed the issue.
///
/// This will return a result with the
/// [Status::SystemError](crate::Status::SystemError) status if the check does
/// not have the [CheckHint::AUTO_FIX](crate::CheckHint::AUTO_FIX) flag set, or
/// an auto-fix returned an error. In the case of the latter, it will include
/// the error with the check result.
///
/// # Examples
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
/// #     type Value = i32;
/// #
/// #     fn value(&self) -> Self::Value {
/// #         self.0
/// #     }
/// # }
/// #
/// # struct IsZeroCheck(i32);
/// #
/// # impl CheckMetadata for IsZeroCheck {
/// #     fn title(&self) -> std::borrow::Cow<str> {
/// #         todo!()
/// #     }
/// #
/// #     fn description(&self) -> std::borrow::Cow<str> {
/// #         todo!()
/// #     }
/// # }
/// #
/// # impl Check for IsZeroCheck {
/// #     type Item = IntItem;
/// #
/// #     type Items = Vec<IntItem>;
/// #
/// #     fn check(&self) -> CheckResult<Self::Item, Self::Items> {
/// #         if self.0 == 0 {
/// #             CheckResult::new_passed("Good", None, true, false)
/// #         } else {
/// #             CheckResult::new_failed("Bad", None, true, false)
/// #         }
/// #     }
/// #
/// #     fn auto_fix(&mut self) -> Result<(), Error> {
/// #         self.0 = 0;
/// #         Ok(())
/// #     }
/// # }
/// #
/// # impl IsZeroCheck {
/// #     pub fn new(value: i32) -> Self{
/// #         Self(value)
/// #     }
/// # }
/// #
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
pub fn auto_fix<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>>(
    check: &mut impl crate::Check<Item = Item, Items = Items>,
) -> crate::CheckResult<Item, Items> {
    let now = std::time::Instant::now();

    if !check.hint().contains(crate::CheckHint::AUTO_FIX) {
        let mut result = crate::CheckResult::new(
            crate::Status::SystemError,
            "Check does not implement auto fix.",
            None,
            false,
            false,
            None,
        );
        result.set_fix_duration(now.elapsed());

        return result;
    }

    if let Err(err) = check.auto_fix() {
        let mut result = crate::CheckResult::new(
            crate::Status::SystemError,
            "Error in auto fix.",
            None,
            false,
            false,
            Some(err),
        );
        result.set_fix_duration(now.elapsed());

        return result;
    }

    let fix_duration = now.elapsed();
    let mut result = run(check);
    result.set_fix_duration(fix_duration);

    result
}
