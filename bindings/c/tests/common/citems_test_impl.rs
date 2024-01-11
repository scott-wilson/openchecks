use cchecks::*;
use std::{
    alloc::{alloc, dealloc, Layout},
    collections::HashMap,
    mem::size_of,
    sync::Mutex,
};

lazy_static::lazy_static! {
    static ref PTR_LAYOUT_MAP: Mutex<HashMap<usize, Layout>> = {
        Mutex::new(HashMap::new())
    };
}

// For some reason, Rust thinks alloc_items is not used, even though it is used
// in test_result.
#[allow(dead_code)]
pub unsafe fn alloc_items<T>(item_count: usize) -> *mut T {
    let item_size = size_of::<T>();
    let layout = Layout::array::<T>(item_size * item_count).unwrap();
    let ptr = alloc(layout) as *mut T;

    let mut cache = PTR_LAYOUT_MAP.lock().unwrap();
    cache.insert(ptr as usize, layout);

    ptr
}

#[no_mangle]
pub unsafe extern "C" fn int_items_destroy_fn(items: *mut CChecksItem) {
    let mut cache = PTR_LAYOUT_MAP.lock().unwrap();

    if let Some(layout) = cache.remove(&(items as usize)) {
        dealloc(items as *mut u8, layout);
    }

    if cache.is_empty() {
        cache.clear();
        cache.shrink_to_fit();
    }
}
