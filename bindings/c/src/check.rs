use std::{
    borrow::Cow,
    ffi::{c_char, CStr, CString},
    ptr::null_mut,
};

pub type CChecksCheckHint = u8;
#[allow(dead_code)]
pub const CCHECKS_CHECK_HINT_NONE: CChecksCheckHint = 0b0;
#[allow(dead_code)]
pub const CCHECKS_CHECK_HINT_AUTO_FIX: CChecksCheckHint = 0b1;

#[repr(C)]
pub struct CChecksBaseCheck {
    pub title_fn: extern "C" fn(&Self) -> *const c_char,
    pub description_fn: extern "C" fn(&Self) -> *const c_char,
    pub hint_fn: extern "C" fn(&Self) -> CChecksCheckHint,
    pub check_fn: extern "C" fn(&Self) -> crate::CChecksCheckResult,
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

#[no_mangle]
pub extern "C" fn cchecks_check_title(check: &CChecksBaseCheck) -> crate::CChecksStringView {
    crate::CChecksStringView::from_ptr((check.title_fn)(check))
}

#[no_mangle]
pub extern "C" fn cchecks_check_description(check: &CChecksBaseCheck) -> crate::CChecksStringView {
    crate::CChecksStringView::from_ptr((check.description_fn)(check))
}

#[no_mangle]
pub extern "C" fn cchecks_check_hint(check: &CChecksBaseCheck) -> CChecksCheckHint {
    (check.hint_fn)(check)
}

fn cchecks_check_hint_into_check_hint(hint: CChecksCheckHint) -> checks::CheckHint {
    checks::CheckHint::from_bits_truncate(hint)
}

#[repr(C)]
pub struct CChecksAutoFixResult {
    pub(crate) status: CChecksAutoFixStatus,
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

#[no_mangle]
pub extern "C" fn cchecks_check_auto_fix_ok() -> CChecksAutoFixResult {
    CChecksAutoFixResult {
        status: CChecksAutoFixStatus::CChecksAutoFixStatusOk,
        message: null_mut(),
    }
}

#[allow(clippy::missing_safety_doc)] // TODO: Remove after documenting
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
