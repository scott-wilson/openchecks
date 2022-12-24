use std::{
    ffi::{c_char, CString},
    ptr::null_mut,
};

#[repr(C)]
pub struct CChecksString {
    string: *mut c_char,
}

impl Drop for CChecksString {
    fn drop(&mut self) {
        if !self.string.is_null() {
            unsafe { CString::from_raw(self.string) };
        }
    }
}

impl CChecksString {
    pub(crate) fn new<T: AsRef<str>>(text: T) -> Self {
        Self {
            string: match CString::new(text.as_ref()) {
                Ok(r) => r.into_raw(),
                Err(_) => null_mut(),
            },
        }
    }
}

#[allow(clippy::missing_safety_doc)] // TODO: Remove after documenting
#[no_mangle]
pub unsafe extern "C" fn cchecks_string_destroy(string: *mut CChecksString) {
    unsafe { string.drop_in_place() }
}

#[repr(C)]
pub struct CChecksStringView {
    string: *const c_char,
}

impl CChecksStringView {
    pub(crate) fn from_ptr(string: *const c_char) -> Self {
        Self { string }
    }
}
