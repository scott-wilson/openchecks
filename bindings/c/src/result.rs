use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    ptr::null_mut,
};

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
///   studio might decide that the error isn't critical enough to always fail if
///   a supervisor approves the fail to pass through.
/// - Error: If the status is CChecksStatusSystemError, then it may also contain
///   the error that caused the result. Other statuses shouldn't contain an
///   error.
/// - Check duration: A diagnostic tool that could be exposed in a user
///   interface to let the user know how long it took to run the check.
/// - Fix duration: A diagnostic tool that could be exposed in a user
///   interface to let the user know how long it took to run the auto-fix.
#[repr(C)]
pub struct CChecksCheckResult {
    pub(crate) status: crate::CChecksStatus,
    pub(crate) message: *mut c_char,
    pub(crate) items: *mut crate::CChecksItems,
    pub(crate) can_fix: bool,
    pub(crate) can_skip: bool,
    pub(crate) error: *mut c_char,
    pub(crate) check_duration: f64,
    pub(crate) fix_duration: f64,
}

impl From<checks::CheckResult<crate::item::ChecksItemWrapper, crate::CChecksItems>>
    for CChecksCheckResult
{
    fn from(
        value: checks::CheckResult<crate::item::ChecksItemWrapper, crate::CChecksItems>,
    ) -> Self {
        let status = (*value.status()).into();
        let message = match CString::new(value.message()) {
            Ok(msg) => msg.into_raw(),
            Err(_) => unsafe { CString::from_vec_unchecked(b"".to_vec()).into_raw() },
        };
        let items = match value.items() {
            Some(items) => {
                let items = items.to_owned();
                let boxed_items = Box::new(items);

                Box::into_raw(boxed_items)
            }
            None => null_mut(),
        };
        let can_fix = value.can_fix();
        let can_skip = value.can_skip();
        let error = match value.error() {
            Some(err) => match CString::new(err.to_string()) {
                Ok(msg) => msg.into_raw(),
                Err(_) => unsafe { CString::from_vec_unchecked(b"".to_vec()).into_raw() },
            },
            None => unsafe { CString::from_vec_unchecked(b"".to_vec()).into_raw() },
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

impl From<CChecksCheckResult>
    for checks::CheckResult<crate::item::ChecksItemWrapper, crate::CChecksItems>
{
    fn from(value: CChecksCheckResult) -> Self {
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
            unsafe {
                let items = value.items;
                let ptr = (*items).ptr;
                let item_size = (*items).item_size;
                let length = (*items).length;
                let destroy_fn = (*items).destroy_fn;

                extern "C" fn destroy_noop(_ptr: *mut crate::CChecksItem) {}
                (*items).ptr = null_mut();
                (*items).item_size = 0;
                (*items).length = 0;
                (*items).destroy_fn = destroy_noop;

                Some(crate::CChecksItems {
                    ptr,
                    item_size,
                    length,
                    destroy_fn,
                })
            }
        };
        let can_fix = value.can_fix;
        let can_skip = value.can_skip;
        let error = if value.error.is_null() {
            None
        } else {
            let msg = unsafe { CStr::from_ptr(value.error) }
                .to_str()
                .unwrap_or("");

            Some(checks::Error::new(msg))
        };

        checks::CheckResult::new(status, message, items, can_fix, can_skip, error)
    }
}

impl Drop for CChecksCheckResult {
    fn drop(&mut self) {
        if !self.message.is_null() {
            unsafe {
                let message = CString::from_raw(self.message);
                drop(message);
            }
        }
        if !self.items.is_null() {
            unsafe { self.items.drop_in_place() }
        }
        if !self.error.is_null() {
            unsafe {
                let error = CString::from_raw(self.error);
                drop(error);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
impl CChecksCheckResult {
    pub(crate) fn new(
        status: crate::CChecksStatus,
        message: *const c_char,
        items: *mut crate::CChecksItem,
        item_size: usize,
        item_count: usize,
        can_fix: bool,
        can_skip: bool,
        error: *const c_char,
        items_destroy_fn: extern "C" fn(*mut crate::CChecksItem) -> (),
    ) -> Self {
        let message = {
            if message.is_null() {
                unsafe { CString::from_vec_unchecked(b"".to_vec()).into_raw() }
            } else {
                unsafe { CStr::from_ptr(message).to_owned().into_raw() }
            }
        };
        let items = if items.is_null() {
            null_mut()
        } else {
            let items = Box::new(crate::cchecks_items_new(
                items,
                item_size,
                item_count,
                items_destroy_fn,
            ));
            Box::into_raw(items)
        };
        let error = {
            if error.is_null() {
                unsafe { CString::from_vec_unchecked(b"".to_vec()).into_raw() }
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
/// It is suggested to use one of the other `cchecks_check_result_*` methods
/// such as cchecks_check_result_passed` for convenience.
///
/// # Safety
///
/// The message pointer must not be null. It is also copied, so the caller may
/// be able to free the memory once the method is called.
///
/// The items can be null if there are no items. Also, the items pointer must be
/// `item_size * item_count` in bytes.
///
/// Error can be a null pointer. It is also copied, so the caller may be able to
/// free the memory once the method is called.
///
/// `items_destroy_fn` must not destroy the items before it destroys the item
/// array, otherwise that will cause a double free.
#[no_mangle]
pub extern "C" fn cchecks_check_result_new(
    status: crate::CChecksStatus,
    message: *const c_char,
    items: *mut crate::CChecksItem,
    item_size: usize,
    item_count: usize,
    can_fix: bool,
    can_skip: bool,
    error: *const c_char,
    items_destroy_fn: extern "C" fn(*mut crate::CChecksItem) -> (),
) -> CChecksCheckResult {
    CChecksCheckResult::new(
        status,
        message,
        items,
        item_size,
        item_count,
        can_fix,
        can_skip,
        error,
        items_destroy_fn,
    )
}

/// Create a new result that passed a check.
///
/// # Safety
///
/// The message pointer must not be null. It is also copied, so the caller may
/// be able to free the memory once the method is called.
///
/// The items can be null if there are no items. Also, the items pointer must be
/// `item_size * item_count` in bytes.
///
/// `items_destroy_fn` must not destroy the items before it destroys the item
/// array, otherwise that will cause a double free.
#[no_mangle]
pub extern "C" fn cchecks_check_result_passed(
    message: *const c_char,
    items: *mut crate::CChecksItem,
    item_size: usize,
    item_count: usize,
    can_fix: bool,
    can_skip: bool,
    items_destroy_fn: extern "C" fn(*mut crate::CChecksItem) -> (),
) -> CChecksCheckResult {
    CChecksCheckResult::new(
        crate::CChecksStatus::CChecksStatusPassed,
        message,
        items,
        item_size,
        item_count,
        can_fix,
        can_skip,
        null_mut(),
        items_destroy_fn,
    )
}

/// Create a new result that skipped a check.
///
/// # Safety
///
/// The message pointer must not be null. It is also copied, so the caller may
/// be able to free the memory once the method is called.
///
/// The items can be null if there are no items. Also, the items pointer must be
/// `item_size * item_count` in bytes.
///
/// `items_destroy_fn` must not destroy the items before it destroys the item
/// array, otherwise that will cause a double free.
#[no_mangle]
pub extern "C" fn cchecks_check_result_skipped(
    message: *const c_char,
    items: *mut crate::CChecksItem,
    item_size: usize,
    item_count: usize,
    can_fix: bool,
    can_skip: bool,
    items_destroy_fn: extern "C" fn(*mut crate::CChecksItem) -> (),
) -> CChecksCheckResult {
    CChecksCheckResult::new(
        crate::CChecksStatus::CChecksStatusSkipped,
        message,
        items,
        item_size,
        item_count,
        can_fix,
        can_skip,
        null_mut(),
        items_destroy_fn,
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
/// The items can be null if there are no items. Also, the items pointer must be
/// `item_size * item_count` in bytes.
///
/// `items_destroy_fn` must not destroy the items before it destroys the item
/// array, otherwise that will cause a double free.
#[no_mangle]
pub extern "C" fn cchecks_check_result_warning(
    message: *const c_char,
    items: *mut crate::CChecksItem,
    item_size: usize,
    item_count: usize,
    can_fix: bool,
    can_skip: bool,
    items_destroy_fn: extern "C" fn(*mut crate::CChecksItem) -> (),
) -> CChecksCheckResult {
    CChecksCheckResult::new(
        crate::CChecksStatus::CChecksStatusWarning,
        message,
        items,
        item_size,
        item_count,
        can_fix,
        can_skip,
        null_mut(),
        items_destroy_fn,
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
/// The items can be null if there are no items. Also, the items pointer must be
/// `item_size * item_count` in bytes.
///
/// `items_destroy_fn` must not destroy the items before it destroys the item
/// array, otherwise that will cause a double free.
#[no_mangle]
pub extern "C" fn cchecks_check_result_failed(
    message: *const c_char,
    items: *mut crate::CChecksItem,
    item_size: usize,
    item_count: usize,
    can_fix: bool,
    can_skip: bool,
    items_destroy_fn: extern "C" fn(*mut crate::CChecksItem) -> (),
) -> CChecksCheckResult {
    CChecksCheckResult::new(
        crate::CChecksStatus::CChecksStatusFailed,
        message,
        items,
        item_size,
        item_count,
        can_fix,
        can_skip,
        null_mut(),
        items_destroy_fn,
    )
}

/// Destroy the result.
///
/// # Safety
///
/// The result pointer must be not null, and must not be already destroyed.
#[no_mangle]
pub unsafe extern "C" fn cchecks_check_result_destroy(result: *mut CChecksCheckResult) {
    unsafe { result.drop_in_place() }
}

/// The status of the result.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub extern "C" fn cchecks_check_result_status(result: &CChecksCheckResult) -> crate::CChecksStatus {
    result.status
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
pub extern "C" fn cchecks_check_result_message(
    result: &CChecksCheckResult,
) -> crate::CChecksStringView {
    crate::CChecksStringView::from_ptr(result.message)
}

/// The items that caused the result.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub extern "C" fn cchecks_check_result_items(
    result: &CChecksCheckResult,
) -> *const crate::CChecksItems {
    result.items
}

/// Whether the result can be fixed or not.
///
/// If the status is `CChecksStatusSystemError`, then the check can **never** be
/// fixed without fixing the issue with the validation system.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub extern "C" fn cchecks_check_result_can_fix(result: &CChecksCheckResult) -> bool {
    match result.status {
        crate::CChecksStatus::CChecksStatusSystemError => false,
        _ => result.can_fix,
    }
}

/// Whether the result can be skipped or not.
///
/// A result should only be skipped if the studio decides that letting the
/// failed check pass will not cause serious issues to the next department.
/// Also, it is recommended that check results are not skipped unless a
/// supervisor overrides the skip.
///
/// If the status is `CChecksStatusSystemError`, then the check can **never** be
/// skipped without fixing the issue with the validation system.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub extern "C" fn cchecks_check_result_can_skip(result: &CChecksCheckResult) -> bool {
    match result.status {
        crate::CChecksStatus::CChecksStatusSystemError => false,
        _ => result.can_skip,
    }
}

/// The error that caused the result.
///
/// This only really applies to the `CChecksStatusSystemError` status. Other
/// results should not include the error object.
///
/// # Safety
///
/// The result pointer must not be null.
#[no_mangle]
pub extern "C" fn cchecks_check_result_error(
    result: &CChecksCheckResult,
) -> crate::CChecksStringView {
    crate::CChecksStringView::from_ptr(result.error)
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
pub extern "C" fn cchecks_check_result_check_duration(result: &CChecksCheckResult) -> f64 {
    result.check_duration
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
pub extern "C" fn cchecks_check_result_fix_duration(result: &CChecksCheckResult) -> f64 {
    result.fix_duration
}
