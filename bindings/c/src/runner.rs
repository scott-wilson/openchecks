#[no_mangle]
pub extern "C" fn cchecks_run(check: &crate::CChecksBaseCheck) -> crate::CChecksCheckResult {
    let result = checks::run(check);
    crate::CChecksCheckResult::from(result)
}

#[no_mangle]
pub extern "C" fn cchecks_auto_fix(
    check: &mut crate::CChecksBaseCheck,
) -> crate::CChecksCheckResult {
    let result = checks::auto_fix(check);
    crate::CChecksCheckResult::from(result)
}
