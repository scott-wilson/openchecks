use cchecks::*;
use std::{
    ffi::{c_char, c_int, c_void, CStr, CString},
    ptr::null_mut,
};

/* ----------------------------------------------------------------------------
  Int Item
*/
#[repr(C)]
pub struct IntItem {
    pub header: cchecks::CChecksItem,
    pub type_hint: *mut c_char,
    pub value: c_int,
}

#[no_mangle]
pub unsafe extern "C" fn int_item_type_hint_fn(item: *const CChecksItem) -> *const c_char {
    let item = item as *const IntItem;
    (*item).type_hint
}

#[no_mangle]
pub unsafe extern "C" fn int_item_value_fn(item: *const CChecksItem) -> *const c_void {
    let item = item as *const IntItem;
    let value = (*item).value;

    (&value) as *const c_int as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn int_item_clone_fn(item: *const CChecksItem, new_item: *mut CChecksItem) {
    let old_item = item as *const IntItem;
    let new_int_item = new_item as *mut IntItem;
    (*new_int_item).header.type_hint_fn = (*item).type_hint_fn;
    (*new_int_item).header.value_fn = (*item).value_fn;
    (*new_int_item).header.clone_fn = (*item).clone_fn;
    (*new_int_item).header.destroy_fn = (*item).destroy_fn;
    (*new_int_item).header.debug_fn = (*item).debug_fn;
    (*new_int_item).header.display_fn = (*item).display_fn;
    (*new_int_item).header.lt_fn = (*item).lt_fn;
    (*new_int_item).header.eq_fn = (*item).eq_fn;

    if (*old_item).type_hint.is_null() {
        (*new_int_item).type_hint = null_mut();
    } else {
        let new_type_hint = CStr::from_ptr((*old_item).type_hint);
        (*new_int_item).type_hint = new_type_hint.to_owned().into_raw();
    }

    (*new_int_item).value = (*old_item).value;
}

#[no_mangle]
pub unsafe extern "C" fn int_item_destroy_fn(item: *mut CChecksItem) {
    let item = item as *mut IntItem;

    if !(*item).type_hint.is_null() {
        drop(CString::from_raw((*item).type_hint));
    }
}

#[no_mangle]
pub unsafe extern "C" fn int_item_debug_fn(item: *const CChecksItem) -> CChecksString {
    return ((*item).display_fn)(item);
}

#[no_mangle]
pub unsafe extern "C" fn int_item_display_fn(item: *const CChecksItem) -> CChecksString {
    let item = item as *const IntItem;
    let value = (*item).value;
    let display_string = CString::new(format!("{}", value)).unwrap().into_raw();

    CChecksString {
        string: display_string,
        destroy_fn: destroy_string_ptr,
    }
}

#[no_mangle]
pub unsafe extern "C" fn int_item_lt_fn(
    item: *const CChecksItem,
    other_item: *const CChecksItem,
) -> bool {
    let item = item as *const IntItem;
    let other_item = other_item as *const IntItem;
    return (*item).value < (*other_item).value;
}

#[no_mangle]
pub unsafe extern "C" fn int_item_eq_fn(
    item: *const CChecksItem,
    other_item: *const CChecksItem,
) -> bool {
    let item = item as *const IntItem;
    let other_item = other_item as *const IntItem;
    return (*item).value == (*other_item).value;
}

#[no_mangle]
pub unsafe extern "C" fn create_int_item(value: c_int, type_hint: *const c_char) -> IntItem {
    let new_type_hint: *mut c_char;

    if !type_hint.is_null() {
        new_type_hint = CStr::from_ptr(type_hint).to_owned().into_raw();
    } else {
        new_type_hint = null_mut();
    }

    let header = CChecksItem {
        type_hint_fn: int_item_type_hint_fn,
        value_fn: int_item_value_fn,
        clone_fn: int_item_clone_fn,
        destroy_fn: int_item_destroy_fn,
        debug_fn: int_item_debug_fn,
        display_fn: int_item_display_fn,
        lt_fn: int_item_lt_fn,
        eq_fn: int_item_eq_fn,
    };
    IntItem {
        header,
        type_hint: new_type_hint,
        value,
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_int_item(item: *mut IntItem) {
    cchecks_item_destroy(item as *mut CChecksItem);
}

/* ----------------------------------------------------------------------------
  String Item
*/
#[repr(C)]
pub struct StringItem {
    pub header: cchecks::CChecksItem,
    pub type_hint: *mut c_char,
    pub value: *mut c_char,
}

#[no_mangle]
pub unsafe extern "C" fn string_item_type_hint_fn(item: *const CChecksItem) -> *const c_char {
    let item = item as *const StringItem;
    (*item).type_hint
}

#[no_mangle]
pub unsafe extern "C" fn string_item_value_fn(item: *const CChecksItem) -> *const c_void {
    let item = item as *const StringItem;
    let value = (*item).value;

    value as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn string_item_clone_fn(
    item: *const CChecksItem,
    new_item: *mut CChecksItem,
) {
    let old_item = item as *const StringItem;
    let new_string_item = new_item as *mut StringItem;
    (*new_string_item).header.type_hint_fn = (*item).type_hint_fn;
    (*new_string_item).header.value_fn = (*item).value_fn;
    (*new_string_item).header.clone_fn = (*item).clone_fn;
    (*new_string_item).header.destroy_fn = (*item).destroy_fn;
    (*new_string_item).header.debug_fn = (*item).debug_fn;
    (*new_string_item).header.display_fn = (*item).display_fn;
    (*new_string_item).header.lt_fn = (*item).lt_fn;
    (*new_string_item).header.eq_fn = (*item).eq_fn;

    if (*old_item).type_hint.is_null() {
        (*new_string_item).type_hint = null_mut();
    } else {
        let new_type_hint = CStr::from_ptr((*old_item).type_hint);
        (*new_string_item).type_hint = new_type_hint.to_owned().into_raw();
    }

    (*new_string_item).value = CStr::from_ptr((*old_item).value).to_owned().into_raw();
}

#[no_mangle]
pub unsafe extern "C" fn string_item_destroy_fn(item: *mut CChecksItem) {
    let item = item as *mut StringItem;

    if !(*item).value.is_null() {
        drop(CString::from_raw((*item).value));
    }

    if !(*item).type_hint.is_null() {
        drop(CString::from_raw((*item).type_hint));
    }
}

#[no_mangle]
pub unsafe extern "C" fn string_item_debug_fn(item: *const CChecksItem) -> CChecksString {
    return ((*item).display_fn)(item);
}

#[no_mangle]
pub unsafe extern "C" fn string_item_display_fn(item: *const CChecksItem) -> CChecksString {
    let item = item as *const StringItem;
    let value = (*item).value;
    let display_string = CString::new(format!("{}", CStr::from_ptr(value).to_string_lossy()))
        .unwrap()
        .into_raw();

    CChecksString {
        string: display_string,
        destroy_fn: destroy_string_ptr,
    }
}

#[no_mangle]
pub unsafe extern "C" fn string_item_lt_fn(
    item: *const CChecksItem,
    other_item: *const CChecksItem,
) -> bool {
    let item = item as *const StringItem;
    let other_item = other_item as *const StringItem;
    return CStr::from_ptr((*item).value) < CStr::from_ptr((*other_item).value);
}

#[no_mangle]
pub unsafe extern "C" fn string_item_eq_fn(
    item: *const CChecksItem,
    other_item: *const CChecksItem,
) -> bool {
    let item = item as *const StringItem;
    let other_item = other_item as *const StringItem;
    return CStr::from_ptr((*item).value) == CStr::from_ptr((*other_item).value);
}

#[no_mangle]
pub unsafe extern "C" fn create_string_item(
    value: *const c_char,
    type_hint: *const c_char,
) -> StringItem {
    let new_type_hint: *mut c_char;
    let value = CStr::from_ptr(value).to_owned().into_raw();

    if !type_hint.is_null() {
        new_type_hint = CStr::from_ptr(type_hint).to_owned().into_raw();
    } else {
        new_type_hint = null_mut();
    }

    let header = CChecksItem {
        type_hint_fn: string_item_type_hint_fn,
        value_fn: string_item_value_fn,
        clone_fn: string_item_clone_fn,
        destroy_fn: string_item_destroy_fn,
        debug_fn: string_item_debug_fn,
        display_fn: string_item_display_fn,
        lt_fn: string_item_lt_fn,
        eq_fn: string_item_eq_fn,
    };
    StringItem {
        header,
        type_hint: new_type_hint,
        value,
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_string_item(item: *mut StringItem) {
    cchecks_item_destroy(item as *mut CChecksItem);
}

/* ----------------------------------------------------------------------------
  Utils
*/
#[no_mangle]
pub unsafe extern "C" fn destroy_string_ptr(string: *mut CChecksString) {
    if !(*string).string.is_null() {
        drop(CString::from_raw((*string).string));
    }
}

#[no_mangle]
pub unsafe extern "C" fn noop_items_destroy_fn(_ptr: *mut CChecksItem) {}
