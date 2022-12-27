use std::{
    borrow::Cow,
    ffi::{c_char, CStr, CString},
    ptr::null_mut,
};

/// The check hint flags contains useful information such as whether the check
/// should support auto-fixing issues.
pub type CChecksCheckHint = u8;
/// The check supports no extra features.
///
/// This should be considered the most conservative check *feature*. For
/// example, no auto-fix, check cannot be skipped before running, etc.
pub const CCHECKS_CHECK_HINT_NONE: CChecksCheckHint = 0b0;
/// The check supports auto-fixing.
///
/// This does not guarantee that the auto-fix is implemented, but instead that
/// the auto-fix should be implemented.
pub const CCHECKS_CHECK_HINT_AUTO_FIX: CChecksCheckHint = 0b1;

#[repr(C)]
pub struct CChecksBaseCheck {
    /// The human readable title for the check.
    ///
    /// User interfaces should use the title for displaying the check.
    pub title_fn: extern "C" fn(&Self) -> *const c_char,

    /// The human readable description for the check.
    ///
    /// This should include information about what the check is looking for,
    /// what are the conditions for the different statuses it supports, and if
    /// there's an auto-fix, what the auto-fix will do.
    pub description_fn: extern "C" fn(&Self) -> *const c_char,

    /// The hint gives information about what features the check supports.
    pub hint_fn: extern "C" fn(&Self) -> CChecksCheckHint,

    /// Run a validation on the input data and output the result of the
    /// validation.
    pub check_fn: extern "C" fn(&Self) -> crate::CChecksCheckResult,

    /// Automatically fix the issue detected by the check method.
    pub auto_fix_fn: Option<extern "C" fn(&Self) -> CChecksAutoFixResult>,
}

impl checks::CheckMetadata for CChecksBaseCheck {
    fn title(&self) -> Cow<str> {
        let ptr = (self.title_fn)(self);

        if ptr.is_null() {
            return "".into();
        }

        unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("").into()
    }

    fn description(&self) -> Cow<str> {
        let ptr = (self.description_fn)(self);

        if ptr.is_null() {
            return "".into();
        }

        unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("").into()
    }

    fn hint(&self) -> checks::CheckHint {
        cchecks_check_hint_into_check_hint((self.hint_fn)(self))
    }
}

impl checks::Check for CChecksBaseCheck {
    type Item = crate::item::ChecksItemWrapper;
    type Items = crate::CChecksItems;

    fn check(&self) -> checks::CheckResult<Self::Item, Self::Items> {
        let c_result = (self.check_fn)(self);
        c_result.into()
    }

    fn auto_fix(&mut self) -> Result<(), checks::Error> {
        match self.auto_fix_fn {
            Some(auto_fix_fn) => {
                let result = auto_fix_fn(self);
                match result.status {
                    CChecksAutoFixStatus::CChecksAutoFixStatusOk => Ok(()),
                    CChecksAutoFixStatus::CChecksAutoFixStatusError => {
                        let message = if result.message.is_null() {
                            ""
                        } else {
                            unsafe { CStr::from_ptr(result.message) }
                                .to_str()
                                .unwrap_or("")
                        };
                        Err(checks::Error::new(message))
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
#[no_mangle]
pub extern "C" fn cchecks_check_title(check: &CChecksBaseCheck) -> crate::CChecksStringView {
    crate::CChecksStringView::from_ptr((check.title_fn)(check))
}

/// The human readable description for the check.
///
/// This should include information about what the check is looking for, what
/// are the conditions for the different statuses it supports, and if there's an
/// auto-fix, what the auto-fix will do.
#[no_mangle]
pub extern "C" fn cchecks_check_description(check: &CChecksBaseCheck) -> crate::CChecksStringView {
    crate::CChecksStringView::from_ptr((check.description_fn)(check))
}

/// Run a validation on the input data and output the result of the validation.
#[no_mangle]
pub extern "C" fn cchecks_check_hint(check: &CChecksBaseCheck) -> CChecksCheckHint {
    (check.hint_fn)(check)
}

fn cchecks_check_hint_into_check_hint(hint: CChecksCheckHint) -> checks::CheckHint {
    checks::CheckHint::from_bits_truncate(hint)
}

/// The result of the auto fix. The message should only contain a value if the
/// auto-fix returned an error.
///
/// # Safety
///
/// The message pointer must not be modified or destroyed. The auto-fix runner
/// is responsible for destroying the message once done.
#[repr(C)]
pub struct CChecksAutoFixResult {
    /// The status of the auto-fix.
    pub(crate) status: CChecksAutoFixStatus,

    /// The error message. Null means no message.
    pub(crate) message: *mut c_char,
}

impl Drop for CChecksAutoFixResult {
    fn drop(&mut self) {
        if !self.message.is_null() {
            let message = unsafe { CString::from_raw(self.message) };
            drop(message)
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CChecksAutoFixStatus {
    CChecksAutoFixStatusOk,
    CChecksAutoFixStatusError,
}

/// The auto-fix was successful, and did not return any errors.
#[no_mangle]
pub extern "C" fn cchecks_check_auto_fix_ok() -> CChecksAutoFixResult {
    CChecksAutoFixResult {
        status: CChecksAutoFixStatus::CChecksAutoFixStatusOk,
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
pub unsafe extern "C" fn cchecks_check_auto_fix_error(
    message: *const c_char,
) -> CChecksAutoFixResult {
    let message = if message.is_null() {
        unsafe { CString::from_vec_unchecked(b"".to_vec()).into_raw() }
    } else {
        unsafe { CStr::from_ptr(message) }.to_owned().into_raw()
    };
    CChecksAutoFixResult {
        status: CChecksAutoFixStatus::CChecksAutoFixStatusError,
        message,
    }
}
