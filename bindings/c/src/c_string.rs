use std::{
    ffi::{c_char, CStr, CString},
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

    pub(crate) fn to_str(&self) -> Option<&str> {
        match unsafe { self.string.as_ref() } {
            Some(ptr) => match unsafe { CStr::from_ptr(ptr) }.to_str() {
                Ok(string) => Some(string),
                Err(_) => None,
            },
            None => None,
        }
    }
}

#[no_mangle]
pub extern "C" fn cchecks_string_destroy(string: *mut CChecksString) {
    drop(string)
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
