use std::{
    ffi::{c_char, c_int, CStr},
    mem::{forget, MaybeUninit},
    ptr::null,
};

use cchecks::*;
mod common;
use common::*;

/* ----------------------------------------------------------------------------
  Checks
*/
#[test]
fn test_item_type_hint_success() {
    unsafe {
        // Test with a hint with text.
        let mut item = create_int_item(1, CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr());
        let cchecks_item = &item as *const IntItem as *const CChecksItem;
        let result = cchecks_item_type_hint(cchecks_item);

        assert_eq!(CStr::from_ptr(result).to_string_lossy(), "test");
        destroy_int_item(&mut item);
        forget(item);

        // Test with a null hint.
        let mut item = create_int_item(1, null());
        let cchecks_item = &item as *const IntItem as *const CChecksItem;
        let result = cchecks_item_type_hint(cchecks_item);

        assert!(result.is_null());
        destroy_int_item(&mut item);
        forget(item);
    }
}

#[test]
fn test_item_value_success() {
    unsafe {
        let mut int_item =
            create_int_item(1, CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr());
        let cchecks_int_item = &int_item as *const IntItem as *const CChecksItem;
        let result = cchecks_item_value(cchecks_int_item);
        let int_result = result as *const c_int;

        assert_eq!(*int_result, 1);
        destroy_int_item(&mut int_item);
        forget(int_item);

        let mut string_item = create_string_item(
            CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr(),
            null(),
        );
        let cchecks_string_item = &string_item as *const StringItem as *const CChecksItem;
        let result = cchecks_item_value(cchecks_string_item);
        let string_result = result as *const c_char;

        assert_eq!(CStr::from_ptr(string_result).to_string_lossy(), "test");
        destroy_string_item(&mut string_item);
        forget(string_item);
    }
}

#[test]
fn test_item_clone_success() {
    unsafe {
        let mut int_item =
            create_int_item(1, CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr());
        let mut new_int_item: MaybeUninit<IntItem> = MaybeUninit::uninit();
        let cchecks_int_item = &int_item as *const IntItem as *const CChecksItem;
        cchecks_item_clone(
            cchecks_int_item,
            new_int_item.as_mut_ptr() as *mut IntItem as *mut CChecksItem,
        );
        let mut new_int_item = new_int_item.assume_init();

        assert_eq!(int_item.value, new_int_item.value);
        assert_eq!(
            CStr::from_ptr(int_item.type_hint),
            CStr::from_ptr(new_int_item.type_hint)
        );
        assert_ne!(
            &int_item.value as *const c_int as usize,
            new_int_item.value as usize
        );
        assert_ne!(
            int_item.type_hint as *mut c_char as usize,
            new_int_item.type_hint as usize
        );

        destroy_int_item(&mut int_item);
        destroy_int_item(&mut new_int_item);
        forget(int_item);
        forget(new_int_item);

        let mut string_item = create_string_item(
            CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr(),
            CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr(),
        );
        let mut new_string_item: MaybeUninit<StringItem> = MaybeUninit::uninit();
        let cchecks_string_item = &string_item as *const StringItem as *const CChecksItem;
        cchecks_item_clone(
            cchecks_string_item,
            new_string_item.as_mut_ptr() as *mut StringItem as *mut CChecksItem,
        );
        let mut new_string_item = new_string_item.assume_init();

        assert_eq!(
            CStr::from_ptr(string_item.value),
            CStr::from_ptr(new_string_item.value)
        );
        assert_eq!(
            CStr::from_ptr(string_item.type_hint),
            CStr::from_ptr(new_string_item.type_hint)
        );
        assert_ne!(
            string_item.value as *const c_char as usize,
            new_string_item.value as usize
        );
        assert_ne!(
            string_item.type_hint as *mut c_char as usize,
            new_string_item.type_hint as usize
        );

        destroy_string_item(&mut string_item);
        destroy_string_item(&mut new_string_item);
        forget(string_item);
        forget(new_string_item);
    }
}

#[test]
fn test_item_debug_success() {
    unsafe {
        let mut int_item =
            create_int_item(1, CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr());
        let cchecks_int_item = &int_item as *const IntItem as *const CChecksItem;
        let mut debug_string = cchecks_item_debug(cchecks_int_item);

        assert_eq!(
            CStr::from_ptr(debug_string.string).to_string_lossy(),
            "Item(1)"
        );
        cchecks_string_destroy(&mut debug_string);
        destroy_int_item(&mut int_item);
        forget(debug_string);
        forget(int_item);

        let mut string_item = create_string_item(
            CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr(),
            CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr(),
        );
        let cchecks_string_item = &string_item as *const StringItem as *const CChecksItem;
        let mut debug_string = cchecks_item_debug(cchecks_string_item);

        assert_eq!(
            CStr::from_ptr(debug_string.string).to_string_lossy(),
            "Item(test)"
        );
        cchecks_string_destroy(&mut debug_string);
        destroy_string_item(&mut string_item);
        forget(debug_string);
        forget(string_item);
    }
}

#[test]
fn test_item_display_success() {
    unsafe {
        let mut int_item =
            create_int_item(1, CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr());
        let cchecks_int_item = &int_item as *const IntItem as *const CChecksItem;
        let mut display_string = cchecks_item_display(cchecks_int_item);

        assert_eq!(CStr::from_ptr(display_string.string).to_string_lossy(), "1");
        cchecks_string_destroy(&mut display_string);
        destroy_int_item(&mut int_item);
        forget(display_string);
        forget(int_item);

        let mut string_item = create_string_item(
            CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr(),
            CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr(),
        );
        let cchecks_string_item = &string_item as *const StringItem as *const CChecksItem;
        let mut display_string = cchecks_item_display(cchecks_string_item);

        assert_eq!(
            CStr::from_ptr(display_string.string).to_string_lossy(),
            "test"
        );
        cchecks_string_destroy(&mut display_string);
        destroy_string_item(&mut string_item);
        forget(display_string);
        forget(string_item);
    }
}

#[test]
fn test_item_lt_success() {
    unsafe {
        // Int: A < B
        let mut a_int_item = create_int_item(1, null());
        let a_cchecks_item = &a_int_item as *const IntItem as *const CChecksItem;
        let mut b_int_item = create_int_item(2, null());
        let b_cchecks_item = &b_int_item as *const IntItem as *const CChecksItem;

        assert!(cchecks_item_lt(a_cchecks_item, b_cchecks_item));

        destroy_int_item(&mut a_int_item);
        destroy_int_item(&mut b_int_item);
        forget(a_int_item);
        forget(b_int_item);

        // Int: A == B
        let mut a_int_item = create_int_item(1, null());
        let a_cchecks_item = &a_int_item as *const IntItem as *const CChecksItem;
        let mut b_int_item = create_int_item(1, null());
        let b_cchecks_item = &b_int_item as *const IntItem as *const CChecksItem;

        assert!(!cchecks_item_lt(a_cchecks_item, b_cchecks_item));
        destroy_int_item(&mut a_int_item);
        destroy_int_item(&mut b_int_item);
        forget(a_int_item);
        forget(b_int_item);

        // Int: A > B
        let mut a_int_item = create_int_item(1, null());
        let a_cchecks_item = &a_int_item as *const IntItem as *const CChecksItem;
        let mut b_int_item = create_int_item(0, null());
        let b_cchecks_item = &b_int_item as *const IntItem as *const CChecksItem;

        assert!(!cchecks_item_lt(a_cchecks_item, b_cchecks_item));
        destroy_int_item(&mut a_int_item);
        destroy_int_item(&mut b_int_item);
        forget(a_int_item);
        forget(b_int_item);

        // String: A < B
        let mut a_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"a\0").as_ptr(), null());
        let a_cchecks_item = &a_string_item as *const StringItem as *const CChecksItem;
        let mut b_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"b\0").as_ptr(), null());
        let b_cchecks_item = &b_string_item as *const StringItem as *const CChecksItem;

        assert!(cchecks_item_lt(a_cchecks_item, b_cchecks_item));

        destroy_string_item(&mut a_string_item);
        destroy_string_item(&mut b_string_item);
        forget(a_string_item);
        forget(b_string_item);

        // String: A == B
        let mut a_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"a\0").as_ptr(), null());
        let a_cchecks_item = &a_string_item as *const StringItem as *const CChecksItem;
        let mut b_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"a\0").as_ptr(), null());
        let b_cchecks_item = &b_string_item as *const StringItem as *const CChecksItem;

        assert!(!cchecks_item_lt(a_cchecks_item, b_cchecks_item));
        destroy_string_item(&mut a_string_item);
        destroy_string_item(&mut b_string_item);
        forget(a_string_item);
        forget(b_string_item);

        // String: A > B
        let mut a_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"b\0").as_ptr(), null());
        let a_cchecks_item = &a_string_item as *const StringItem as *const CChecksItem;
        let mut b_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"a\0").as_ptr(), null());
        let b_cchecks_item = &b_string_item as *const StringItem as *const CChecksItem;

        assert!(!cchecks_item_lt(a_cchecks_item, b_cchecks_item));
        destroy_string_item(&mut a_string_item);
        destroy_string_item(&mut b_string_item);
        forget(a_string_item);
        forget(b_string_item);
    }
}

#[test]
fn test_item_eq_success() {
    unsafe {
        let mut a_int_item = create_int_item(1, null());
        let a_cchecks_item = &a_int_item as *const IntItem as *const CChecksItem;
        let mut b_int_item = create_int_item(1, null());
        let b_cchecks_item = &b_int_item as *const IntItem as *const CChecksItem;

        assert!(cchecks_item_eq(a_cchecks_item, b_cchecks_item));

        destroy_int_item(&mut a_int_item);
        destroy_int_item(&mut b_int_item);
        forget(a_int_item);
        forget(b_int_item);

        let mut a_int_item = create_int_item(1, null());
        let a_cchecks_item = &a_int_item as *const IntItem as *const CChecksItem;
        let mut b_int_item = create_int_item(2, null());
        let b_cchecks_item = &b_int_item as *const IntItem as *const CChecksItem;

        assert!(!cchecks_item_eq(a_cchecks_item, b_cchecks_item));
        destroy_int_item(&mut a_int_item);
        destroy_int_item(&mut b_int_item);
        forget(a_int_item);
        forget(b_int_item);

        let mut a_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"1\0").as_ptr(), null());
        let a_cchecks_item = &a_string_item as *const StringItem as *const CChecksItem;
        let mut b_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"1\0").as_ptr(), null());
        let b_cchecks_item = &b_string_item as *const StringItem as *const CChecksItem;

        assert!(cchecks_item_eq(a_cchecks_item, b_cchecks_item));

        destroy_string_item(&mut a_string_item);
        destroy_string_item(&mut b_string_item);
        forget(a_string_item);
        forget(b_string_item);

        let mut a_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"1\0").as_ptr(), null());
        let a_cchecks_item = &a_string_item as *const StringItem as *const CChecksItem;
        let mut b_string_item =
            create_string_item(CStr::from_bytes_with_nul_unchecked(b"2\0").as_ptr(), null());
        let b_cchecks_item = &b_string_item as *const StringItem as *const CChecksItem;

        assert!(!cchecks_item_eq(a_cchecks_item, b_cchecks_item));
        destroy_string_item(&mut a_string_item);
        destroy_string_item(&mut b_string_item);
        forget(a_string_item);
        forget(b_string_item);
    }
}
