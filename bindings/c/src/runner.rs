/// Run a check.
///
/// # Safety
///
/// The check pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_run(
    check: *const crate::OpenChecksBaseCheck,
) -> crate::OpenChecksCheckResult {
    let check = match unsafe { check.as_ref() } {
        Some(c) => c,
        None => {
            return base_openchecks::CheckResult::new(
                base_openchecks::Status::SystemError,
                "openchecks_run received a null pointer.",
                None,
                false,
                false,
                Some(base_openchecks::Error::new(
                    "openchecks_run received a null pointer.",
                )),
            )
            .into()
        }
    };
    let result = base_openchecks::run(check);
    crate::OpenChecksCheckResult::from(result)
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
/// This will return a result with the `OpenChecksStatusSystemError` status if
/// the check does not have the CheckHint::AUTO_FIX flag set, or an auto-fix
/// returned an error. In the case of the latter, it will include the error with
/// the check result.
///
/// # Safety
///
/// The check pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_auto_fix(
    check: *mut crate::OpenChecksBaseCheck,
) -> crate::OpenChecksCheckResult {
    let check = match unsafe { check.as_mut() } {
        Some(c) => c,
        None => {
            return base_openchecks::CheckResult::new(
                base_openchecks::Status::SystemError,
                "openchecks_auto_fix received a null pointer.",
                None,
                false,
                false,
                Some(base_openchecks::Error::new(
                    "openchecks_auto_fix received a null pointer.",
                )),
            )
            .into()
        }
    };
    let result = base_openchecks::auto_fix(check);
    crate::OpenChecksCheckResult::from(result)
}
