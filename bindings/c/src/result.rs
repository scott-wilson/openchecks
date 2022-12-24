use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
    ptr::null_mut,
};

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

#[allow(clippy::missing_safety_doc)] // TODO: Remove when documenting
#[no_mangle]
pub unsafe extern "C" fn cchecks_check_result_destroy(result: *mut CChecksCheckResult) {
    unsafe { result.drop_in_place() }
}

#[no_mangle]
pub extern "C" fn cchecks_check_result_status(result: &CChecksCheckResult) -> crate::CChecksStatus {
    result.status
}

#[no_mangle]
pub extern "C" fn cchecks_check_result_message(
    result: &CChecksCheckResult,
) -> crate::CChecksStringView {
    crate::CChecksStringView::from_ptr(result.message)
}

#[no_mangle]
pub extern "C" fn cchecks_check_result_items(
    result: &CChecksCheckResult,
) -> *const crate::CChecksItems {
    result.items
}

#[no_mangle]
pub extern "C" fn cchecks_check_result_can_fix(result: &CChecksCheckResult) -> bool {
    match result.status {
        crate::CChecksStatus::CChecksStatusSystemError => false,
        _ => result.can_fix,
    }
}

#[no_mangle]
pub extern "C" fn cchecks_check_result_can_skip(result: &CChecksCheckResult) -> bool {
    match result.status {
        crate::CChecksStatus::CChecksStatusSystemError => false,
        _ => result.can_skip,
    }
}

#[no_mangle]
pub extern "C" fn cchecks_check_result_error(
    result: &CChecksCheckResult,
) -> crate::CChecksStringView {
    crate::CChecksStringView::from_ptr(result.error)
}

#[no_mangle]
pub extern "C" fn cchecks_check_result_check_duration(result: &CChecksCheckResult) -> f64 {
    result.check_duration
}

#[no_mangle]
pub extern "C" fn cchecks_check_result_fix_duration(result: &CChecksCheckResult) -> f64 {
    result.fix_duration
}
