use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    ptr::null_mut,
};

use crate::openchecks_items_destroy;

/// A check result contains all of the information needed to know the status of
/// a check.
///
/// It contains useful information such as...
///
/// - Status: A machine readable value that can be used to quickly tell whether
///   the test passed, failed, or is pending.
/// - Message: A human readable description of the status. If the status failed,
///   this should contain information on what happened, and how to fix the
///   issue.
/// - Items: An iterable of items that caused the result. For example, if a
///   check that validates if objects are named correctly failed, then the items
///   would include the offending objects.
/// - Can fix: Whether the check can be fixed or not. For example, if a check
///   requires textures to be no larger than a certain size, includes a method
///   to resize the textures, and failed, the result could be marked as fixable
///   so the user could press an "auto-fix" button in a user interface to resize
///   the textures.
/// - Can skip: Usually, a validation system should not let any checks that
///   failed to go forward with, for example, publishing an asset. Sometimes a
///   company might decide that the error isn't critical enough to always fail
///   if a supervisor approves the fail to pass through.
/// - Error: If the status is OpenChecksStatusSystemError, then it may also
///   contain the error that caused the result. Other statuses shouldn't contain
///   an error.
/// - Check duration: A diagnostic tool that could be exposed in a user
///   interface to let the user know how long it took to run the check.
/// - Fix duration: A diagnostic tool that could be exposed in a user
///   interface to let the user know how long it took to run the auto-fix.
#[repr(C)]
pub struct OpenChecksCheckResult {
    pub status: crate::OpenChecksStatus,
    pub message: *mut c_char,
    pub items: *mut crate::OpenChecksItems,
    pub can_fix: bool,
    pub can_skip: bool,
    pub error: *mut c_char,
    pub check_duration: f64,
    pub fix_duration: f64,
}

impl
    From<
        base_openchecks::CheckResult<
            crate::item::ChecksItemWrapper,
            crate::items::OpenChecksItemsWrapper,
        >,
    > for OpenChecksCheckResult
{
    fn from(
        value: base_openchecks::CheckResult<
            crate::item::ChecksItemWrapper,
            crate::items::OpenChecksItemsWrapper,
        >,
    ) -> Self {
        let status = (*value.status()).into();
        let message = match CString::new(value.message()) {
            Ok(msg) => msg.into_raw(),
            Err(_) => CStr::from_bytes_with_nul(b"\0")
                .unwrap()
                .to_owned()
                .into_raw(),
        };
        let items = match value.items() {
            Some(items) => unsafe { crate::openchecks_items_clone(items.ptr) },
            None => null_mut(),
        };
        let can_fix = value.can_fix();
        let can_skip = value.can_skip();
        let error = match value.error() {
            Some(err) => match CString::new(err.to_string()) {
                Ok(msg) => msg.into_raw(),
                Err(_) => CStr::from_bytes_with_nul(b"\0")
                    .unwrap()
                    .to_owned()
                    .into_raw(),
            },
            None => null_mut(),
        };
        let check_duration = value.check_duration().as_secs_f64();
        let fix_duration = value.fix_duration().as_secs_f64();

        Self {
            status,
            message,
            items,
            can_fix,
            can_skip,
            error,
            check_duration,
            fix_duration,
        }
    }
}

impl From<OpenChecksCheckResult>
    for base_openchecks::CheckResult<
        crate::item::ChecksItemWrapper,
        crate::items::OpenChecksItemsWrapper,
    >
{
    fn from(value: OpenChecksCheckResult) -> Self {
        let mut value = value;
        let status = value.status.into();
        let message = unsafe {
            if value.message.is_null() {
                ""
            } else {
                CStr::from_ptr(value.message).to_str().unwrap_or("")
            }
        };
        let items = if value.items.is_null() {
            None
        } else {
            let items = value.items;
            value.items = null_mut();

            Some(crate::items::OpenChecksItemsWrapper { ptr: items })
        };
        let can_fix = value.can_fix;
        let can_skip = value.can_skip;
        let error = if value.error.is_null() {
            None
        } else {
            let msg = unsafe { CStr::from_ptr(value.error) }
                .to_str()
                .unwrap_or("");

            Some(base_openchecks::Error::new(msg))
        };

        base_openchecks::CheckResult::new(status, message, items, can_fix, can_skip, error)
    }
}

impl Drop for OpenChecksCheckResult {
    fn drop(&mut self) {
        if !self.message.is_null() {
            unsafe {
                let message = CString::from_raw(self.message);
                drop(message);
                self.message = null_mut();
            }
        }
        if !self.items.is_null() {
            unsafe {
                openchecks_items_destroy(self.items);
                self.items = null_mut();
            }
        }
        if !self.error.is_null() {
            unsafe {
                let error = CString::from_raw(self.error);
                drop(error);
                self.error = null_mut();
            }
        }
    }
}

impl OpenChecksCheckResult {
    pub(crate) fn new(
        status: crate::OpenChecksStatus,
        message: *const c_char,
        items: *mut crate::OpenChecksItems,
        can_fix: bool,
        can_skip: bool,
        error: *const c_char,
    ) -> Self {
        let message = {
            if message.is_null() {
                CStr::from_bytes_with_nul(b"\0")
                    .unwrap()
                    .to_owned()
                    .into_raw()
            } else {
                unsafe { CStr::from_ptr(message).to_owned().into_raw() }
            }
        };
        let error = {
            if error.is_null() {
                null_mut()
            } else {
                unsafe { CStr::from_ptr(error).to_owned().into_raw() }
            }
        };

        Self {
            status,
            message,
            items,
            can_fix,
            can_skip,
            error,
            check_duration: 0.0,
            fix_duration: 0.0,
        }
    }
}

/// Create a new result.
///
/// It is suggested to use one of the other `openchecks_check_result_*` methods
/// such as `openchecks_check_result_passed` for convenience.
///
/// # Safety
///
/// The message pointer must not be null. It is also copied, so the caller may
/// be able to free the memory once the method is called.
///
/// The items can be null if there are no items. Also, the result will take
/// ownership of the pointer and be responsible for cleaning it once the result
/// is destroyed.
///
/// Error can be a null pointer. It is also copied, so the caller may be able to
/// free the memory once the method is called.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_new(
    status: crate::OpenChecksStatus,
    message: *const c_char,
    items: *mut crate::OpenChecksItems,
    can_fix: bool,
    can_skip: bool,
    error: *const c_char,
) -> OpenChecksCheckResult {
    OpenChecksCheckResult::new(status, message, items, can_fix, can_skip, error)
}

/// Create a new result that passed a check.
///
/// # Safety
///
/// The message pointer must not be null. It is also copied, so the caller may
/// be able to free the memory once the method is called.
///
/// The items can be null if there are no items. Also, the result will take
/// ownership of the pointer and be responsible for cleaning it once the result
/// is destroyed.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_passed(
    message: *const c_char,
    items: *mut crate::OpenChecksItems,
    can_fix: bool,
    can_skip: bool,
) -> OpenChecksCheckResult {
    OpenChecksCheckResult::new(
        crate::OpenChecksStatus::OpenChecksStatusPassed,
        message,
        items,
        can_fix,
        can_skip,
        null_mut(),
    )
}

/// Create a new result that skipped a check.
///
/// # Safety
///
/// The message pointer must not be null. It is also copied, so the caller may
/// be able to free the memory once the method is called.
///
/// The items can be null if there are no items. Also, the result will take
/// ownership of the pointer and be responsible for cleaning it once the result
/// is destroyed.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_skipped(
    message: *const c_char,
    items: *mut crate::OpenChecksItems,
    can_fix: bool,
    can_skip: bool,
) -> OpenChecksCheckResult {
    OpenChecksCheckResult::new(
        crate::OpenChecksStatus::OpenChecksStatusSkipped,
        message,
        items,
        can_fix,
        can_skip,
        null_mut(),
    )
}

/// Create a new result that passed a check, but with a warning.
///
/// Warnings should be considered as passes, but with notes saying that there
/// *may* be an issue. For example, textures could be any resolution, but
/// anything over 4096x4096 could be marked as a potential performance issue.
///
/// # Safety
///
/// The message pointer must not be null. It is also copied, so the caller may
/// be able to free the memory once the method is called.
///
/// The items can be null if there are no items. Also, the result will take
/// ownership of the pointer and be responsible for cleaning it once the result
/// is destroyed.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_warning(
    message: *const c_char,
    items: *mut crate::OpenChecksItems,
    can_fix: bool,
    can_skip: bool,
) -> OpenChecksCheckResult {
    OpenChecksCheckResult::new(
        crate::OpenChecksStatus::OpenChecksStatusWarning,
        message,
        items,
        can_fix,
        can_skip,
        null_mut(),
    )
}

/// Create a new result that failed a check.
///
/// Failed checks in a validation system should not let the following process
/// continue forward unless the check can be skipped/overridden by a supervisor,
/// or is fixed and later passes, or passes with a warning.
///
/// # Safety
///
/// The message pointer must not be null. It is also copied, so the caller may
/// be able to free the memory once the method is called.
///
/// The items can be null if there are no items. Also, the result will take
/// ownership of the pointer and be responsible for cleaning it once the result
/// is destroyed.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_failed(
    message: *const c_char,
    items: *mut crate::OpenChecksItems,
    can_fix: bool,
    can_skip: bool,
) -> OpenChecksCheckResult {
    OpenChecksCheckResult::new(
        crate::OpenChecksStatus::OpenChecksStatusFailed,
        message,
        items,
        can_fix,
        can_skip,
        null_mut(),
    )
}

/// Destroy the result.
///
/// # Safety
///
/// The result pointer must be not null, and must not be already destroyed.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_destroy(result: *mut OpenChecksCheckResult) {
    unsafe { result.drop_in_place() }
}

/// The status of the result.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_status(
    result: *const OpenChecksCheckResult,
) -> crate::OpenChecksStatus {
    (*result).status
}

/// A human readable message for the result.
///
/// If a check has issues, then this should include information about what
/// happened and how to fix the issue.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_message(
    result: *const OpenChecksCheckResult,
) -> crate::OpenChecksStringView {
    crate::OpenChecksStringView::from_ptr((*result).message)
}

/// The items that caused the result.
///
/// # Safety
///
/// A null result pointer represents that there are no items.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_items(
    result: &OpenChecksCheckResult,
) -> *const crate::OpenChecksItems {
    result.items
}

/// Whether the result can be fixed or not.
///
/// If the status is `OpenChecksStatusSystemError`, then the check can **never**
/// be fixed without fixing the issue with the validation system.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_can_fix(
    result: *const OpenChecksCheckResult,
) -> bool {
    match (*result).status {
        crate::OpenChecksStatus::OpenChecksStatusSystemError => false,
        _ => (*result).can_fix,
    }
}

/// Whether the result can be skipped or not.
///
/// A result should only be skipped if the company decides that letting the
/// failed check pass will not cause serious issues to the next department.
/// Also, it is recommended that check results are not skipped unless a
/// supervisor overrides the skip.
///
/// If the status is `OpenChecksStatusSystemError`, then the check can **never**
/// be skipped without fixing the issue with the validation system.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_can_skip(
    result: *const OpenChecksCheckResult,
) -> bool {
    match (*result).status {
        crate::OpenChecksStatus::OpenChecksStatusSystemError => false,
        _ => (*result).can_skip,
    }
}

/// The error that caused the result.
///
/// This only really applies to the `OpenChecksStatusSystemError` status. Other
/// results should not include the error object.
///
/// # Safety
///
/// The result pointer is null if there are no errors. Otherwise it will point
/// to a valid message.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_error(
    result: *const OpenChecksCheckResult,
) -> *const std::ffi::c_char {
    (*result).error
}

/// The duration of a check.
///
/// This is not settable outside of the check runner. It can be exposed to a
/// user to let them know how long a check took to run, or be used as a
/// diagnostics tool to improve check performance.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_check_duration(
    result: *const OpenChecksCheckResult,
) -> f64 {
    (*result).check_duration
}

/// The duration of an auto-fix.
///
/// This is not settable outside of the auto-fix runner. It can be exposed to a
/// user to let them know how long an auto-fix took to run, or be used as a
/// diagnostics tool to improve check performance.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_result_fix_duration(
    result: *const OpenChecksCheckResult,
) -> f64 {
    (*result).fix_duration
}
