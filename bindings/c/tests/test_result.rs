use std::{
    ffi::{c_int, CStr},
    mem::{forget, size_of},
    ptr::{null, null_mut},
};

use cchecks::*;
mod common;
use common::*;

/* ----------------------------------------------------------------------------
  Checks
*/
#[test]
fn test_cchecks_check_result_new() {
    unsafe {
        let status = CChecksStatus::CChecksStatusPassed;
        let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
        let item_count = 5;
        let item_size = size_of::<IntItem>();
        let items: *mut IntItem = alloc_items(item_count);

        for i in 0..item_size {
            items
                .add(i)
                .write(create_int_item(i.try_into().unwrap(), null()))
        }

        let can_fix = false;
        let can_skip = false;
        let error = null();

        let mut result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );

        // Status
        assert_eq!(cchecks_check_result_status(&result) as u8, status as u8);
        // Message
        let result_message = cchecks_check_result_message(&result);
        assert_eq!(
            CStr::from_ptr(result_message.string),
            CStr::from_ptr(message)
        );
        // Items
        let result_items = cchecks_check_result_items(&result);
        assert!(!result_items.is_null());
        assert_eq!((*result_items).length, item_count);
        assert_eq!((*result_items).item_size, item_size);

        let mut items_iter = cchecks_items_iterator_new(result_items);
        let mut index = 0;
        let mut item;

        while !cchecks_item_iterator_is_done(&items_iter) {
            item = cchecks_item_iterator_item(&mut items_iter);
            assert_eq!(*(cchecks_item_value(item) as *const c_int), index);
            index += 1;
            cchecks_item_iterator_next(&mut items_iter);
        }

        // Can fix
        assert_eq!(cchecks_check_result_can_fix(&result), can_fix);

        // Can skip
        assert_eq!(cchecks_check_result_can_skip(&result), can_skip);

        // Error
        let result_error = cchecks_check_result_error(&result);
        assert_eq!(CStr::from_ptr(result_error.string).to_string_lossy(), "");

        // Cleanup
        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_passed() {
    unsafe {
        let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
        let item_count = 5;
        let item_size = size_of::<IntItem>();
        let items: *mut IntItem = alloc_items(item_count);

        for i in 0..item_size {
            items
                .add(i)
                .write(create_int_item(i.try_into().unwrap(), null()))
        }

        let can_fix = false;
        let can_skip = false;

        let mut result = cchecks_check_result_passed(
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            int_items_destroy_fn,
        );

        // Status
        assert_eq!(
            cchecks_check_result_status(&result) as u8,
            CChecksStatus::CChecksStatusPassed as u8
        );
        // Message
        let result_message = cchecks_check_result_message(&result);
        assert_eq!(
            CStr::from_ptr(result_message.string),
            CStr::from_ptr(message)
        );
        // Items
        let result_items = cchecks_check_result_items(&result);
        assert!(!result_items.is_null());
        assert_eq!((*result_items).length, item_count);
        assert_eq!((*result_items).item_size, item_size);

        let mut items_iter = cchecks_items_iterator_new(result_items);
        let mut index = 0;
        let mut item;

        while !cchecks_item_iterator_is_done(&items_iter) {
            item = cchecks_item_iterator_item(&mut items_iter);
            assert_eq!(*(cchecks_item_value(item) as *const c_int), index);
            index += 1;
            cchecks_item_iterator_next(&mut items_iter);
        }

        // Can fix
        assert_eq!(cchecks_check_result_can_fix(&result), can_fix);

        // Can skip
        assert_eq!(cchecks_check_result_can_skip(&result), can_skip);

        // Cleanup
        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_skipped() {
    unsafe {
        let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
        let item_count = 5;
        let item_size = size_of::<IntItem>();
        let items: *mut IntItem = alloc_items(item_count);

        for i in 0..item_size {
            items
                .add(i)
                .write(create_int_item(i.try_into().unwrap(), null()))
        }

        let can_fix = false;
        let can_skip = false;

        let mut result = cchecks_check_result_skipped(
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            int_items_destroy_fn,
        );

        // Status
        assert_eq!(
            cchecks_check_result_status(&result) as u8,
            CChecksStatus::CChecksStatusSkipped as u8
        );
        // Message
        let result_message = cchecks_check_result_message(&result);
        assert_eq!(
            CStr::from_ptr(result_message.string),
            CStr::from_ptr(message)
        );
        // Items
        let result_items = cchecks_check_result_items(&result);
        assert!(!result_items.is_null());
        assert_eq!((*result_items).length, item_count);
        assert_eq!((*result_items).item_size, item_size);

        let mut items_iter = cchecks_items_iterator_new(result_items);
        let mut index = 0;
        let mut item;

        while !cchecks_item_iterator_is_done(&items_iter) {
            item = cchecks_item_iterator_item(&mut items_iter);
            assert_eq!(*(cchecks_item_value(item) as *const c_int), index);
            index += 1;
            cchecks_item_iterator_next(&mut items_iter);
        }

        // Can fix
        assert_eq!(cchecks_check_result_can_fix(&result), can_fix);

        // Can skip
        assert_eq!(cchecks_check_result_can_skip(&result), can_skip);

        // Cleanup
        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_warning() {
    unsafe {
        let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
        let item_count = 5;
        let item_size = size_of::<IntItem>();
        let items: *mut IntItem = alloc_items(item_count);

        for i in 0..item_size {
            items
                .add(i)
                .write(create_int_item(i.try_into().unwrap(), null()))
        }

        let can_fix = false;
        let can_skip = false;

        let mut result = cchecks_check_result_warning(
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            int_items_destroy_fn,
        );

        // Status
        assert_eq!(
            cchecks_check_result_status(&result) as u8,
            CChecksStatus::CChecksStatusWarning as u8
        );
        // Message
        let result_message = cchecks_check_result_message(&result);
        assert_eq!(
            CStr::from_ptr(result_message.string),
            CStr::from_ptr(message)
        );
        // Items
        let result_items = cchecks_check_result_items(&result);
        assert!(!result_items.is_null());
        assert_eq!((*result_items).length, item_count);
        assert_eq!((*result_items).item_size, item_size);

        let mut items_iter = cchecks_items_iterator_new(result_items);
        let mut index = 0;
        let mut item;

        while !cchecks_item_iterator_is_done(&items_iter) {
            item = cchecks_item_iterator_item(&mut items_iter);
            assert_eq!(*(cchecks_item_value(item) as *const c_int), index);
            index += 1;
            cchecks_item_iterator_next(&mut items_iter);
        }

        // Can fix
        assert_eq!(cchecks_check_result_can_fix(&result), can_fix);

        // Can skip
        assert_eq!(cchecks_check_result_can_skip(&result), can_skip);

        // Cleanup
        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_failed() {
    unsafe {
        let message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
        let item_count = 5;
        let item_size = size_of::<IntItem>();
        let items: *mut IntItem = alloc_items(item_count);

        for i in 0..item_size {
            items
                .add(i)
                .write(create_int_item(i.try_into().unwrap(), null()))
        }

        let can_fix = false;
        let can_skip = false;

        let mut result = cchecks_check_result_failed(
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            int_items_destroy_fn,
        );

        // Status
        assert_eq!(
            cchecks_check_result_status(&result) as u8,
            CChecksStatus::CChecksStatusFailed as u8
        );
        // Message
        let result_message = cchecks_check_result_message(&result);
        assert_eq!(
            CStr::from_ptr(result_message.string),
            CStr::from_ptr(message)
        );
        // Items
        let result_items = cchecks_check_result_items(&result);
        assert!(!result_items.is_null());
        assert_eq!((*result_items).length, item_count);
        assert_eq!((*result_items).item_size, item_size);

        let mut items_iter = cchecks_items_iterator_new(result_items);
        let mut index = 0;
        let mut item;

        while !cchecks_item_iterator_is_done(&items_iter) {
            item = cchecks_item_iterator_item(&mut items_iter);
            assert_eq!(*(cchecks_item_value(item) as *const c_int), index);
            index += 1;
            cchecks_item_iterator_next(&mut items_iter);
        }

        // Can fix
        assert_eq!(cchecks_check_result_can_fix(&result), can_fix);

        // Can skip
        assert_eq!(cchecks_check_result_can_skip(&result), can_skip);

        // Cleanup
        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_destroy() {
    unsafe {
        let mut status;
        let mut message;
        let mut item_count;
        let mut item_size;
        let mut items: *mut IntItem;
        let mut can_fix;
        let mut can_skip;
        let mut error;
        let mut result;

        // All pointers null.
        status = CChecksStatus::CChecksStatusPassed;
        message = null();
        item_count = 0;
        item_size = 0;
        items = null_mut();
        can_fix = false;
        can_skip = false;
        error = null();

        result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );
        cchecks_check_result_destroy(&mut result);
        forget(result);

        // No pointers null.
        status = CChecksStatus::CChecksStatusPassed;
        message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
        item_count = 5;
        item_size = size_of::<IntItem>();
        items = alloc_items(item_count);
        can_fix = false;
        can_skip = false;
        error = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();

        for i in 0..item_size {
            items
                .add(i)
                .write(create_int_item(i.try_into().unwrap(), null()))
        }

        result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );
        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_status() {
    unsafe {
        let mut status;
        let mut message;
        let mut item_count;
        let mut item_size;
        let mut items: *mut IntItem;
        let mut can_fix;
        let mut can_skip;
        let mut error;
        let mut result;

        let statuses = [
            CChecksStatus::CChecksStatusPending,
            CChecksStatus::CChecksStatusSkipped,
            CChecksStatus::CChecksStatusPassed,
            CChecksStatus::CChecksStatusWarning,
            CChecksStatus::CChecksStatusFailed,
            CChecksStatus::CChecksStatusSystemError,
        ];

        for i in 0..6 {
            status = statuses[i];
            message = null();
            item_count = 0;
            item_size = 0;
            items = null_mut();
            can_fix = false;
            can_skip = false;
            error = null();
            result = cchecks_check_result_new(
                status,
                message,
                items as *mut IntItem as *mut CChecksItem,
                item_size,
                item_count,
                can_fix,
                can_skip,
                error,
                int_items_destroy_fn,
            );
            assert_eq!(cchecks_check_result_status(&result) as u8, status as u8);
            cchecks_check_result_destroy(&mut result);
            forget(result);
        }
    }
}

#[test]
fn test_cchecks_check_result_message() {
    unsafe {
        let mut status;
        let mut message;
        let mut item_count;
        let mut item_size;
        let mut items: *mut IntItem;
        let mut can_fix;
        let mut can_skip;
        let mut error;
        let mut result;
        let mut msg;

        // Null message.
        status = CChecksStatus::CChecksStatusPassed;
        message = null();
        item_count = 0;
        item_size = 0;
        items = null_mut();
        can_fix = false;
        can_skip = false;
        error = null();

        result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );
        msg = cchecks_check_result_message(&result);
        assert_eq!(CStr::from_ptr(msg.string).to_string_lossy(), "");
        cchecks_check_result_destroy(&mut result);
        forget(result);

        // Non-null message.
        status = CChecksStatus::CChecksStatusPassed;
        message = CStr::from_bytes_with_nul_unchecked(b"test\0").as_ptr();
        item_count = 0;
        item_size = 0;
        items = null_mut();
        can_fix = false;
        can_skip = false;
        error = null();

        result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );
        msg = cchecks_check_result_message(&result);
        assert_eq!(CStr::from_ptr(msg.string).to_string_lossy(), "test");
        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_items() {
    unsafe {
        let mut status;
        let mut message;
        let mut item_count;
        let mut item_size;
        let mut items: *mut IntItem;
        let mut can_fix;
        let mut can_skip;
        let mut error;
        let mut result;
        let mut result_items;
        let mut items_iter;
        let mut item;

        // Null items.
        status = CChecksStatus::CChecksStatusPassed;
        message = null();
        item_count = 0;
        item_size = 0;
        items = null_mut();
        can_fix = false;
        can_skip = false;
        error = null();

        result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );
        result_items = cchecks_check_result_items(&result);
        assert!(result_items.is_null());

        items_iter = cchecks_items_iterator_new(result_items);
        assert_eq!(items_iter.index, 0);
        assert_eq!(items_iter.items, result_items);
        assert!(items_iter.items.is_null());

        cchecks_check_result_destroy(&mut result);
        forget(result);

        // 0 items.
        status = CChecksStatus::CChecksStatusPassed;
        message = null();
        item_count = 0;
        item_size = size_of::<IntItem>();
        items = alloc_items(item_count);
        can_fix = false;
        can_skip = false;
        error = null();

        result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );
        result_items = cchecks_check_result_items(&result);
        assert!(!result_items.is_null());
        assert_eq!((*result_items).item_size, item_size);
        assert_eq!((*result_items).length, item_count);
        assert!(!(*result_items).ptr.is_null());

        items_iter = cchecks_items_iterator_new(result_items);
        assert_eq!(items_iter.index, 0);
        assert_eq!(items_iter.items, result_items);
        assert!(!items_iter.items.is_null());

        assert!(cchecks_item_iterator_is_done(&items_iter));
        assert!(cchecks_item_iterator_item(&mut items_iter).is_null());
        assert!(cchecks_item_iterator_next(&mut items_iter).is_null());

        cchecks_check_result_destroy(&mut result);
        forget(result);

        // 1 item.
        status = CChecksStatus::CChecksStatusPassed;
        message = null();
        item_count = 1;
        item_size = size_of::<IntItem>();
        items = alloc_items(item_count);
        can_fix = false;
        can_skip = false;
        error = null();

        items.add(0).write(create_int_item(1, null()));

        result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );
        result_items = cchecks_check_result_items(&result);
        assert!(!result_items.is_null());
        assert_eq!((*result_items).item_size, item_size);
        assert_eq!((*result_items).length, item_count);
        assert!(!(*result_items).ptr.is_null());

        items_iter = cchecks_items_iterator_new(result_items);
        assert_eq!(items_iter.index, 0);
        assert_eq!(items_iter.items, result_items);
        assert!(!items_iter.items.is_null());

        assert!(!cchecks_item_iterator_is_done(&items_iter));
        item = cchecks_item_iterator_item(&mut items_iter);
        assert!(!item.is_null());
        assert_eq!(*(cchecks_item_value(item) as *const c_int), 1);
        item = cchecks_item_iterator_next(&mut items_iter);
        assert!(cchecks_item_iterator_is_done(&items_iter));
        assert_eq!(items_iter.index, 1);
        assert!(!item.is_null());
        assert_eq!(*(cchecks_item_value(item) as *const c_int), 1);
        item = cchecks_item_iterator_item(&mut items_iter);
        assert!(item.is_null());

        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_can_fix() {
    unsafe {
        let mut status;
        let mut message;
        let mut item_count;
        let mut item_size;
        let mut items: *mut IntItem;
        let mut can_fix;
        let mut can_skip;
        let mut error;
        let mut result;

        let statuses = [
            CChecksStatus::CChecksStatusPending,
            CChecksStatus::CChecksStatusSkipped,
            CChecksStatus::CChecksStatusPassed,
            CChecksStatus::CChecksStatusWarning,
            CChecksStatus::CChecksStatusFailed,
            CChecksStatus::CChecksStatusSystemError,
        ];

        // can_fix = true.
        let expected = [true, true, true, true, true, false];

        for i in 0..6 {
            status = statuses[i];
            message = null();
            item_count = 0;
            item_size = 0;
            items = null_mut();
            can_fix = true;
            can_skip = false;
            error = null();

            result = cchecks_check_result_new(
                status,
                message,
                items as *mut IntItem as *mut CChecksItem,
                item_size,
                item_count,
                can_fix,
                can_skip,
                error,
                int_items_destroy_fn,
            );

            assert_eq!(cchecks_check_result_can_fix(&result), expected[i]);
            cchecks_check_result_destroy(&mut result);
            forget(result);
        }

        // can_fix = false.
        for i in 0..6 {
            status = statuses[i];
            message = null();
            item_count = 0;
            item_size = 0;
            items = null_mut();
            can_fix = false;
            can_skip = false;
            error = null();

            result = cchecks_check_result_new(
                status,
                message,
                items as *mut IntItem as *mut CChecksItem,
                item_size,
                item_count,
                can_fix,
                can_skip,
                error,
                int_items_destroy_fn,
            );

            assert_eq!(cchecks_check_result_can_fix(&result), false);
            cchecks_check_result_destroy(&mut result);
            forget(result);
        }
    }
}

#[test]
fn test_cchecks_check_result_can_skip() {
    unsafe {
        let mut status;
        let mut message;
        let mut item_count;
        let mut item_size;
        let mut items: *mut IntItem;
        let mut can_fix;
        let mut can_skip;
        let mut error;
        let mut result;

        let statuses = [
            CChecksStatus::CChecksStatusPending,
            CChecksStatus::CChecksStatusSkipped,
            CChecksStatus::CChecksStatusPassed,
            CChecksStatus::CChecksStatusWarning,
            CChecksStatus::CChecksStatusFailed,
            CChecksStatus::CChecksStatusSystemError,
        ];

        // can_fix = true.
        let expected = [true, true, true, true, true, false];

        for i in 0..6 {
            status = statuses[i];
            message = null();
            item_count = 0;
            item_size = 0;
            items = null_mut();
            can_fix = false;
            can_skip = true;
            error = null();

            result = cchecks_check_result_new(
                status,
                message,
                items as *mut IntItem as *mut CChecksItem,
                item_size,
                item_count,
                can_fix,
                can_skip,
                error,
                int_items_destroy_fn,
            );

            assert_eq!(cchecks_check_result_can_skip(&result), expected[i]);
            cchecks_check_result_destroy(&mut result);
            forget(result);
        }

        // can_fix = false.
        for i in 0..6 {
            status = statuses[i];
            message = null();
            item_count = 0;
            item_size = 0;
            items = null_mut();
            can_fix = false;
            can_skip = false;
            error = null();

            result = cchecks_check_result_new(
                status,
                message,
                items as *mut IntItem as *mut CChecksItem,
                item_size,
                item_count,
                can_fix,
                can_skip,
                error,
                int_items_destroy_fn,
            );

            assert_eq!(cchecks_check_result_can_skip(&result), false);
            cchecks_check_result_destroy(&mut result);
            forget(result);
        }
    }
}

#[test]
fn test_cchecks_check_result_error() {
    unsafe {
        let mut status;
        let mut message;
        let mut item_count;
        let mut item_size;
        let mut items: *mut IntItem;
        let mut can_fix;
        let mut can_skip;
        let mut error;
        let mut result;
        let mut msg;

        // Null error.
        status = CChecksStatus::CChecksStatusPassed;
        message = null();
        item_count = 0;
        item_size = 0;
        items = null_mut();
        can_fix = false;
        can_skip = false;
        error = null();

        result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );
        msg = cchecks_check_result_error(&result);
        assert_eq!(CStr::from_ptr(msg.string).to_string_lossy(), "");
        cchecks_check_result_destroy(&mut result);
        forget(result);

        // Non-null message.
        status = CChecksStatus::CChecksStatusPassed;
        message = null();
        item_count = 0;
        item_size = 0;
        items = null_mut();
        can_fix = false;
        can_skip = false;
        error = CStr::from_bytes_with_nul_unchecked(b"error\0").as_ptr();

        result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );
        msg = cchecks_check_result_error(&result);
        assert_eq!(CStr::from_ptr(msg.string).to_string_lossy(), "error");
        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_check_duration() {
    unsafe {
        let status = CChecksStatus::CChecksStatusPassed;
        let message = null();
        let item_count = 0;
        let item_size = 0;
        let items: *mut IntItem = null_mut();

        let can_fix = false;
        let can_skip = false;
        let error = null();

        let mut result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );

        assert_eq!(cchecks_check_result_check_duration(&result), 0.0,);

        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}

#[test]
fn test_cchecks_check_result_fix_duration() {
    unsafe {
        let status = CChecksStatus::CChecksStatusPassed;
        let message = null();
        let item_count = 0;
        let item_size = 0;
        let items: *mut IntItem = null_mut();

        let can_fix = false;
        let can_skip = false;
        let error = null();

        let mut result = cchecks_check_result_new(
            status,
            message,
            items as *mut IntItem as *mut CChecksItem,
            item_size,
            item_count,
            can_fix,
            can_skip,
            error,
            int_items_destroy_fn,
        );

        assert_eq!(cchecks_check_result_fix_duration(&result), 0.0);

        cchecks_check_result_destroy(&mut result);
        forget(result);
    }
}
