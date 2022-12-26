/// Run a check.
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
