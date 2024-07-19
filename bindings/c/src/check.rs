use std::{
    borrow::Cow,
    ffi::{c_char, CStr, CString},
    ptr::null_mut,
};

/// The check hint flags contains useful information such as whether the check
/// should support auto-fixing issues.
pub type OpenChecksCheckHint = u8;
/// The check supports no extra features.
///
/// This should be considered the most conservative check *feature*. For
/// example, no auto-fix, check cannot be skipped before running, etc.
pub const OPENCHECKS_CHECK_HINT_NONE: OpenChecksCheckHint = 0b0;
/// The check supports auto-fixing.
///
/// This does not guarantee that the auto-fix is implemented, but instead that
/// the auto-fix should be implemented.
pub const OPENCHECKS_CHECK_HINT_AUTO_FIX: OpenChecksCheckHint = 0b1;

#[repr(C)]
pub struct OpenChecksBaseCheck {
    /// The human readable title for the check.
    ///
    /// User interfaces should use the title for displaying the check.
    pub title_fn: unsafe extern "C" fn(*const Self) -> *const c_char,

    /// The human readable description for the check.
    ///
    /// This should include information about what the check is looking for,
    /// what are the conditions for the different statuses it supports, and if
    /// there's an auto-fix, what the auto-fix will do.
    pub description_fn: unsafe extern "C" fn(*const Self) -> *const c_char,

    /// The hint gives information about what features the check supports.
    pub hint_fn: unsafe extern "C" fn(*const Self) -> OpenChecksCheckHint,

    /// Run a validation on the input data and output the result of the
    /// validation.
    pub check_fn: unsafe extern "C" fn(*const Self) -> crate::OpenChecksCheckResult,

    /// Automatically fix the issue detected by the check method.
    pub auto_fix_fn: Option<unsafe extern "C" fn(*mut Self) -> OpenChecksAutoFixResult>,
}

impl base_openchecks::CheckMetadata for OpenChecksBaseCheck {
    fn title(&self) -> Cow<str> {
        let ptr = unsafe { (self.title_fn)(self) };

        if ptr.is_null() {
            return "".into();
        }

        unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("").into()
    }

    fn description(&self) -> Cow<str> {
        let ptr = unsafe { (self.description_fn)(self) };

        if ptr.is_null() {
            return "".into();
        }

        unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("").into()
    }

    fn hint(&self) -> base_openchecks::CheckHint {
        openchecks_check_hint_into_check_hint(unsafe { (self.hint_fn)(self) })
    }
}

impl base_openchecks::Check for OpenChecksBaseCheck {
    type Item = crate::item::ChecksItemWrapper;
    type Items = crate::items::OpenChecksItemsWrapper;

    fn check(&self) -> base_openchecks::CheckResult<Self::Item, Self::Items> {
        let c_result = unsafe { (self.check_fn)(self) };
        c_result.into()
    }

    fn auto_fix(&mut self) -> Result<(), base_openchecks::Error> {
        match self.auto_fix_fn {
            Some(auto_fix_fn) => {
                let result = unsafe { auto_fix_fn(self) };
                match result.status {
                    OpenChecksAutoFixStatus::OpenChecksAutoFixStatusOk => Ok(()),
                    OpenChecksAutoFixStatus::OpenChecksAutoFixStatusError => {
                        let message = if result.message.is_null() {
                            ""
                        } else {
                            unsafe { CStr::from_ptr(result.message) }
                                .to_str()
                                .unwrap_or("")
                        };
                        Err(base_openchecks::Error::new(message))
                    }
                }
            }
            None => Ok(()),
        }
    }
}

/// The human readable title for the check.
///
/// User interfaces should use the title for displaying the check.
///
/// # Safety
///
/// The pointer should not be null, and point to valid memory.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_title(
    check: *const OpenChecksBaseCheck,
) -> crate::OpenChecksStringView {
    crate::OpenChecksStringView::from_ptr(((*check).title_fn)(check))
}

/// The human readable description for the check.
///
/// This should include information about what the check is looking for, what
/// are the conditions for the different statuses it supports, and if there's an
/// auto-fix, what the auto-fix will do.
///
/// # Safety
///
/// The pointer should not be null, and point to valid memory.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_description(
    check: *const OpenChecksBaseCheck,
) -> crate::OpenChecksStringView {
    crate::OpenChecksStringView::from_ptr(((*check).description_fn)(check))
}

/// Run a validation on the input data and output the result of the validation.
///
/// # Safety
///
/// The pointer should not be null, and point to valid memory.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_hint(
    check: *const OpenChecksBaseCheck,
) -> OpenChecksCheckHint {
    ((*check).hint_fn)(check)
}

fn openchecks_check_hint_into_check_hint(hint: OpenChecksCheckHint) -> base_openchecks::CheckHint {
    base_openchecks::CheckHint::from_bits_truncate(hint)
}

/// The result of the auto fix. The message should only contain a value if the
/// auto-fix returned an error.
///
/// # Safety
///
/// The message pointer must not be modified or destroyed. The auto-fix runner
/// is responsible for destroying the message once done.
#[repr(C)]
pub struct OpenChecksAutoFixResult {
    /// The status of the auto-fix.
    pub status: OpenChecksAutoFixStatus,

    /// The error message. Null means no message.
    pub message: *mut c_char,
}

impl Drop for OpenChecksAutoFixResult {
    fn drop(&mut self) {
        if !self.message.is_null() {
            let message = unsafe { CString::from_raw(self.message) };
            drop(message)
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum OpenChecksAutoFixStatus {
    OpenChecksAutoFixStatusOk,
    OpenChecksAutoFixStatusError,
}

/// The auto-fix was successful, and did not return any errors.
///
/// # Safety
///
/// The pointer should not be null, and point to valid memory.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_auto_fix_ok() -> OpenChecksAutoFixResult {
    OpenChecksAutoFixResult {
        status: OpenChecksAutoFixStatus::OpenChecksAutoFixStatusOk,
        message: null_mut(),
    }
}

/// The auto-fix returned an error.
///
/// # Safety
///
/// The message string will be copied, so the caller may destroy the string
/// after calling this method. Also, a null pointer will be converted to an
/// empty string.
#[no_mangle]
pub unsafe extern "C" fn openchecks_check_auto_fix_error(
    message: *const c_char,
) -> OpenChecksAutoFixResult {
    let message = if message.is_null() {
        CStr::from_bytes_with_nul(b"\0")
            .unwrap()
            .to_owned()
            .into_raw()
    } else {
        unsafe { CStr::from_ptr(message) }.to_owned().into_raw()
    };
    OpenChecksAutoFixResult {
        status: OpenChecksAutoFixStatus::OpenChecksAutoFixStatusError,
        message,
    }
}
