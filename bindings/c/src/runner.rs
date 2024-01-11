/// Run a check.
///
/// # Safety
///
/// The check pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_run(
    check: *const crate::CChecksBaseCheck,
) -> crate::CChecksCheckResult {
    let check = match unsafe { check.as_ref() } {
        Some(c) => c,
        None => {
            return checks::CheckResult::new(
                checks::Status::SystemError,
                "cchecks_run received a null pointer.",
                None,
                false,
                false,
                Some(checks::Error::new("cchecks_run received a null pointer.")),
            )
            .into()
        }
    };
    let result = checks::run(check);
    crate::CChecksCheckResult::from(result)
}

/// Automatically fix an issue found by a check.
///
/// This function should only be run after the check runner returns a result,
/// and that result can be fixed. Otherwise, the fix might try to fix an already
/// "good" object, causing issues with the object.
///
/// The auto-fix will re-run the check runner to validate that it has actually
/// fixed the issue.
///
/// This will return a result with the `CChecksStatusSystemError` status if the
/// check does not have the CheckHint::AUTO_FIX flag set, or an auto-fix
/// returned an error. In the case of the latter, it will include the error with
/// the check result.
///
/// # Safety
///
/// The check pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_auto_fix(
    check: *mut crate::CChecksBaseCheck,
) -> crate::CChecksCheckResult {
    let check = match unsafe { check.as_mut() } {
        Some(c) => c,
        None => {
            return checks::CheckResult::new(
                checks::Status::SystemError,
                "cchecks_auto_fix received a null pointer.",
                None,
                false,
                false,
                Some(checks::Error::new(
                    "cchecks_auto_fix received a null pointer.",
                )),
            )
            .into()
        }
    };
    let result = checks::auto_fix(check);
    crate::CChecksCheckResult::from(result)
}
