use std::{
    ffi::{c_char, CStr},
    mem::MaybeUninit,
    os::raw::c_void,
};

#[derive(Debug, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ChecksItemWrapper(*const CChecksItem);

impl ChecksItemWrapper {
    pub(crate) fn new(item: *const CChecksItem) -> Self {
        Self(item)
    }

    pub(crate) fn ptr(&self) -> *const CChecksItem {
        self.0
    }
}

impl std::fmt::Display for ChecksItemWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_null() {
            // TODO: Should we do a null check?
            panic!()
        }

        write!(f, "{}", unsafe { &*self.0 })
    }
}

#[repr(C)]
pub struct CChecksItem {
    pub type_hint_fn: extern "C" fn(&Self) -> *const c_char,
    pub value_fn: extern "C" fn(&Self) -> *const c_void,
    pub clone_fn: extern "C" fn(&Self, &mut Self),
    pub destroy_fn: extern "C" fn(&mut Self) -> (),
    pub debug_fn: extern "C" fn(&Self) -> *mut c_char,
    pub display_fn: extern "C" fn(&Self) -> *mut c_char,
    pub lt_fn: extern "C" fn(&Self, &Self) -> bool,
    pub eq_fn: extern "C" fn(&Self, &Self) -> bool,
}

impl std::clone::Clone for CChecksItem {
    fn clone(&self) -> Self {
        let mut item = MaybeUninit::<Self>::uninit();

        unsafe {
            (self.clone_fn)(self, &mut *item.as_mut_ptr());

            item.assume_init()
        }
    }
}

impl Drop for CChecksItem {
    fn drop(&mut self) {
        (self.destroy_fn)(self)
    }
}

impl std::fmt::Display for CChecksItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c_display = (self.display_fn)(self);

        if c_display.is_null() {
            return Err(std::fmt::Error);
        }

        unsafe {
            let c_str = CStr::from_ptr(c_display);
            let result = match c_str.to_str() {
                Ok(s) => write!(f, "{}", s),
                Err(_) => Err(std::fmt::Error),
            };
            libc::free(c_display as *mut c_void);

            result
        }
    }
}

impl std::fmt::Debug for CChecksItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c_display = (self.debug_fn)(self);

        if c_display.is_null() {
            return Err(std::fmt::Error);
        }

        unsafe {
            let c_str = CStr::from_ptr(c_display);
            let result = match c_str.to_str() {
                Ok(s) => write!(f, "Item({})", s),
                Err(_) => Err(std::fmt::Error),
            };
            libc::free(c_display as *mut c_void);

            result
        }
    }
}

impl std::cmp::PartialEq for CChecksItem {
    fn eq(&self, other: &Self) -> bool {
        (self.eq_fn)(self, other)
    }
}

impl std::cmp::PartialOrd for CChecksItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if (self.lt_fn)(self, other) {
            Some(std::cmp::Ordering::Less)
        } else if (self.eq_fn)(self, other) {
            Some(std::cmp::Ordering::Equal)
        } else {
            Some(std::cmp::Ordering::Greater)
        }
    }
}

impl checks::Item for CChecksItem {
    type Value = *const c_void;

    fn value(&self) -> Self::Value {
        (self.value_fn)(self)
    }
}

impl checks::Item for ChecksItemWrapper {
    type Value = *const c_void;

    fn value(&self) -> Self::Value {
        let item = unsafe {
            if self.0.is_null() {
                // TODO: Should panic?
                panic!()
            }
            &(*self.0)
        };
        (item.value_fn)(item)
    }
}

#[no_mangle]
pub extern "C" fn cchecks_item_type_hint(item: &CChecksItem) -> *const c_char {
    (item.type_hint_fn)(item)
}

#[no_mangle]
pub extern "C" fn cchecks_item_value(item: &CChecksItem) -> *const c_void {
    (item.value_fn)(item)
}

#[no_mangle]
pub extern "C" fn cchecks_item_clone(item: &CChecksItem, new_item: &mut CChecksItem) {
    (item.clone_fn)(item, new_item)
}

#[no_mangle]
pub extern "C" fn cchecks_item_destroy(item: &mut CChecksItem) {
    (item.destroy_fn)(item)
}

#[no_mangle]
pub extern "C" fn cchecks_item_debug(item: &CChecksItem) -> crate::CChecksString {
    let result = format!("{:?}", item);

    crate::CChecksString::new(result)
}

#[no_mangle]
pub extern "C" fn cchecks_item_display(item: &CChecksItem) -> crate::CChecksString {
    let result = format!("{}", item);
    crate::CChecksString::new(result)
}

#[no_mangle]
pub extern "C" fn cchecks_item_lt(item: &CChecksItem, other: &CChecksItem) -> bool {
    item < other
}

#[no_mangle]
pub extern "C" fn cchecks_item_eq(item: &CChecksItem, other: &CChecksItem) -> bool {
    item == other
}
