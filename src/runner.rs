pub async fn async_run<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>>(
    check: &impl crate::AsyncCheck<Item = Item, Items = Items>,
) -> crate::CheckResult<Item, Items> {
    let now = std::time::Instant::now();

    let mut result = check.async_check().await;

    result.set_check_duration(now.elapsed());

    result
}

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

pub fn run<Item: crate::Item, Items: std::iter::IntoIterator<Item = Item>>(
    check: &impl crate::Check<Item = Item, Items = Items>,
) -> crate::CheckResult<Item, Items> {
    let now = std::time::Instant::now();

    let mut result = check.check();

    result.set_check_duration(now.elapsed());

    result
}

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
