use super::citem_test_impl::noop_items_destroy_fn;
use cchecks::*;
use std::{
    ffi::{c_char, CStr},
    ptr::null_mut,
};

/* ----------------------------------------------------------------------------
  Test check
*/
#[repr(C)]
pub struct TestCheck {
    header: CChecksBaseCheck,
}

#[no_mangle]
pub unsafe extern "C" fn test_check_title_fn(_check: *const CChecksBaseCheck) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"title\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn test_check_description_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"description\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn test_check_hint_fn(_check: *const CChecksBaseCheck) -> CChecksCheckHint {
    CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX
}

#[no_mangle]
pub unsafe extern "C" fn test_check_run_fn(_check: *const CChecksBaseCheck) -> CChecksCheckResult {
    let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
    cchecks_check_result_passed(
        message,
        null_mut(),
        0,
        0,
        false,
        false,
        noop_items_destroy_fn,
    )
}

#[no_mangle]
pub unsafe extern "C" fn test_check_auto_fix_fn(
    _check: *mut CChecksBaseCheck,
) -> CChecksAutoFixResult {
    cchecks_check_auto_fix_ok()
}

#[no_mangle]
pub unsafe extern "C" fn create_test_check() -> TestCheck {
    let header = CChecksBaseCheck {
        title_fn: test_check_title_fn,
        description_fn: test_check_description_fn,
        hint_fn: test_check_hint_fn,
        check_fn: test_check_run_fn,
        auto_fix_fn: Some(test_check_auto_fix_fn),
    };

    TestCheck { header }
}

/* ----------------------------------------------------------------------------
  Always pass check
*/
#[repr(C)]
pub struct AlwaysPassCheck {
    header: CChecksBaseCheck,
}

#[no_mangle]
pub unsafe extern "C" fn always_pass_check_title_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"Always Pass Check\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn always_pass_check_description_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"description\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn always_pass_check_hint_fn(
    _check: *const CChecksBaseCheck,
) -> CChecksCheckHint {
    CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX
}

#[no_mangle]
pub unsafe extern "C" fn always_pass_check_run_fn(
    _check: *const CChecksBaseCheck,
) -> CChecksCheckResult {
    let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
    cchecks_check_result_passed(
        message,
        null_mut(),
        0,
        0,
        false,
        false,
        noop_items_destroy_fn,
    )
}

#[no_mangle]
pub unsafe extern "C" fn create_always_pass_check() -> AlwaysPassCheck {
    let header = CChecksBaseCheck {
        title_fn: always_pass_check_title_fn,
        description_fn: always_pass_check_description_fn,
        hint_fn: always_pass_check_hint_fn,
        check_fn: always_pass_check_run_fn,
        auto_fix_fn: None,
    };

    AlwaysPassCheck { header }
}

/* ----------------------------------------------------------------------------
  Always fail check
*/
#[repr(C)]
pub struct AlwaysFailCheck {
    header: CChecksBaseCheck,
}

#[no_mangle]
pub unsafe extern "C" fn always_fail_check_title_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"Always Fail Check\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn always_fail_check_description_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"description\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn always_fail_check_hint_fn(
    _check: *const CChecksBaseCheck,
) -> CChecksCheckHint {
    CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX
}

#[no_mangle]
pub unsafe extern "C" fn always_fail_check_run_fn(
    _check: *const CChecksBaseCheck,
) -> CChecksCheckResult {
    let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
    cchecks_check_result_failed(
        message,
        null_mut(),
        0,
        0,
        false,
        false,
        noop_items_destroy_fn,
    )
}

#[no_mangle]
pub unsafe extern "C" fn create_always_fail_check() -> AlwaysFailCheck {
    let header = CChecksBaseCheck {
        title_fn: always_fail_check_title_fn,
        description_fn: always_fail_check_description_fn,
        hint_fn: always_fail_check_hint_fn,
        check_fn: always_fail_check_run_fn,
        auto_fix_fn: None,
    };

    AlwaysFailCheck { header }
}

/* ----------------------------------------------------------------------------
  Pass on fix check
*/
#[repr(C)]
pub struct PassOnFixCheck {
    header: CChecksBaseCheck,
    value: u8,
}

#[no_mangle]
pub unsafe extern "C" fn pass_on_fix_check_title_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"Pass On Fix Check\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn pass_on_fix_check_description_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"description\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn pass_on_fix_check_hint_fn(
    _check: *const CChecksBaseCheck,
) -> CChecksCheckHint {
    CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX
}

#[no_mangle]
pub unsafe extern "C" fn pass_on_fix_check_run_fn(
    check: *const CChecksBaseCheck,
) -> CChecksCheckResult {
    let check = check as *const PassOnFixCheck;
    let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();

    if (*check).value != 0 {
        cchecks_check_result_failed(
            message,
            null_mut(),
            0,
            0,
            true,
            false,
            noop_items_destroy_fn,
        )
    } else {
        cchecks_check_result_passed(
            message,
            null_mut(),
            0,
            0,
            false,
            false,
            noop_items_destroy_fn,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn pass_on_fix_auto_fix_fn(
    check: *mut CChecksBaseCheck,
) -> CChecksAutoFixResult {
    let check = check as *mut PassOnFixCheck;
    (*check).value = 0;

    cchecks_check_auto_fix_ok()
}

#[no_mangle]
pub unsafe extern "C" fn create_pass_on_fix_check() -> PassOnFixCheck {
    let header = CChecksBaseCheck {
        title_fn: pass_on_fix_check_title_fn,
        description_fn: pass_on_fix_check_description_fn,
        hint_fn: pass_on_fix_check_hint_fn,
        check_fn: pass_on_fix_check_run_fn,
        auto_fix_fn: Some(pass_on_fix_auto_fix_fn),
    };

    PassOnFixCheck { header, value: 1 }
}

/* ----------------------------------------------------------------------------
  Fail on fix check
*/
#[repr(C)]
pub struct FailOnFixCheck {
    header: CChecksBaseCheck,
    value: u8,
}

#[no_mangle]
pub unsafe extern "C" fn fail_on_fix_check_title_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"Fail On Fix Check\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn fail_on_fix_check_description_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"description\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn fail_on_fix_check_hint_fn(
    _check: *const CChecksBaseCheck,
) -> CChecksCheckHint {
    CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX
}

#[no_mangle]
pub unsafe extern "C" fn fail_on_fix_check_run_fn(
    check: *const CChecksBaseCheck,
) -> CChecksCheckResult {
    let check = check as *const FailOnFixCheck;
    let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();

    if (*check).value != 0 {
        cchecks_check_result_failed(
            message,
            null_mut(),
            0,
            0,
            true,
            false,
            noop_items_destroy_fn,
        )
    } else {
        cchecks_check_result_passed(
            message,
            null_mut(),
            0,
            0,
            false,
            false,
            noop_items_destroy_fn,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn fail_on_fix_auto_fix_fn(
    check: *mut CChecksBaseCheck,
) -> CChecksAutoFixResult {
    let check = check as *mut FailOnFixCheck;
    (*check).value = 2;

    cchecks_check_auto_fix_ok()
}

#[no_mangle]
pub unsafe extern "C" fn create_fail_on_fix_check() -> FailOnFixCheck {
    let header = CChecksBaseCheck {
        title_fn: fail_on_fix_check_title_fn,
        description_fn: fail_on_fix_check_description_fn,
        hint_fn: fail_on_fix_check_hint_fn,
        check_fn: fail_on_fix_check_run_fn,
        auto_fix_fn: Some(fail_on_fix_auto_fix_fn),
    };

    FailOnFixCheck { header, value: 1 }
}

/* ----------------------------------------------------------------------------
  No auto-fix flag check
*/
#[repr(C)]
pub struct NoAutoFixFlagCheck {
    header: CChecksBaseCheck,
    value: u8,
}

#[no_mangle]
pub unsafe extern "C" fn no_auto_fix_flag_check_title_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"No Auto Fix Flag Check\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn no_auto_fix_flag_check_description_fn(
    _check: *const CChecksBaseCheck,
) -> *const c_char {
    CStr::from_bytes_with_nul_unchecked(b"description\0").as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn no_auto_fix_flag_check_hint_fn(
    _check: *const CChecksBaseCheck,
) -> CChecksCheckHint {
    CCHECKS_CHECK_HINT_NONE
}

#[no_mangle]
pub unsafe extern "C" fn no_auto_fix_flag_check_run_fn(
    check: *const CChecksBaseCheck,
) -> CChecksCheckResult {
    let check = check as *const NoAutoFixFlagCheck;
    let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();

    if (*check).value != 0 {
        cchecks_check_result_failed(
            message,
            null_mut(),
            0,
            0,
            true,
            false,
            noop_items_destroy_fn,
        )
    } else {
        cchecks_check_result_passed(
            message,
            null_mut(),
            0,
            0,
            false,
            false,
            noop_items_destroy_fn,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn create_no_auto_fix_flag_check() -> NoAutoFixFlagCheck {
    let header = CChecksBaseCheck {
        title_fn: no_auto_fix_flag_check_title_fn,
        description_fn: no_auto_fix_flag_check_description_fn,
        hint_fn: no_auto_fix_flag_check_hint_fn,
        check_fn: no_auto_fix_flag_check_run_fn,
        auto_fix_fn: None,
    };

    NoAutoFixFlagCheck { header, value: 1 }
}
