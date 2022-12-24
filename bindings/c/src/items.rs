use std::ptr::{null, null_mut};

use crate::item::cchecks_item_clone;

#[repr(C)]
pub struct CChecksItems {
    pub ptr: *mut crate::CChecksItem,
    pub item_size: usize,
    pub length: usize,
    pub destroy_fn: extern "C" fn(*mut crate::CChecksItem) -> (),
}

impl Drop for CChecksItems {
    fn drop(&mut self) {
        unsafe {
            if let Some(ptr) = self.ptr.as_mut() {
                for index in 0..self.length {
                    let item = self
                        .ptr
                        .cast::<u8>()
                        .add(index * self.item_size)
                        .cast::<crate::CChecksItem>();
                    item.drop_in_place()
                }

                (self.destroy_fn)(ptr);
            }
        }
    }
}

impl std::iter::IntoIterator for CChecksItems {
    type Item = crate::item::ChecksItemWrapper;
    type IntoIter = CChecksItemsIterator;

    fn into_iter(self) -> Self::IntoIter {
        CChecksItemsIterator::new(&self)
    }
}

impl Clone for CChecksItems {
    fn clone(&self) -> Self {
        let ptr = if self.ptr.is_null() {
            null_mut()
        } else {
            let size = self.item_size * self.length;

            if size == 0 {
                null_mut()
            } else {
                let ptr = unsafe { libc::malloc(size) };
                let ptr = ptr.cast::<u8>();

                for (index, item) in cchecks_items_iterator_new(self).enumerate() {
                    let item_ptr = unsafe { ptr.add(index).cast::<crate::CChecksItem>() };
                    unsafe {
                        cchecks_item_clone(
                            item.ptr().as_ref().unwrap(),
                            item_ptr.as_mut().unwrap(),
                        );
                    }
                }

                ptr.cast::<crate::CChecksItem>()
            }
        };

        extern "C" fn destroy_cloned_items(ptr: *mut crate::CChecksItem) {
            unsafe { libc::free(ptr as *mut libc::c_void) }
        }

        Self {
            ptr: ptr,
            item_size: self.item_size,
            length: self.length,
            destroy_fn: destroy_cloned_items,
        }
    }
}

#[no_mangle]
pub extern "C" fn cchecks_items_new(
    items: *mut crate::CChecksItem,
    item_size: usize,
    length: usize,
    destroy_fn: extern "C" fn(*mut crate::CChecksItem) -> (),
) -> CChecksItems {
    CChecksItems {
        ptr: items,
        item_size,
        length,
        destroy_fn,
    }
}

#[no_mangle]
pub extern "C" fn cchecks_items_iterator_new(items: &CChecksItems) -> CChecksItemsIterator {
    CChecksItemsIterator { items, index: 0 }
}

#[repr(C)]
pub struct CChecksItemsIterator {
    pub items: *const CChecksItems,
    pub index: usize,
}

impl CChecksItemsIterator {
    pub(crate) fn item(&self) -> Option<<Self as Iterator>::Item> {
        unsafe {
            if self.index >= (*self.items).length {
                return None;
            }

            let result = (*self.items)
                .ptr
                .cast::<u8>()
                .offset((self.index * (*self.items).item_size) as isize)
                .cast::<crate::CChecksItem>();

            Some(crate::item::ChecksItemWrapper::new(result))
        }
    }
}

impl Iterator for CChecksItemsIterator {
    type Item = crate::item::ChecksItemWrapper;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.item();
        self.index += 1;

        item
    }
}

impl CChecksItemsIterator {
    fn new(items: *const CChecksItems) -> Self {
        Self { items, index: 0 }
    }
}

#[no_mangle]
pub extern "C" fn cchecks_item_iterator_next(
    iterator: *mut CChecksItemsIterator,
) -> *const crate::CChecksItem {
    unsafe {
        match (*iterator).next() {
            Some(item) => item.ptr(),
            None => null(),
        }
    }
}

#[no_mangle]
pub extern "C" fn cchecks_item_iterator_item(
    iterator: *mut CChecksItemsIterator,
) -> *const crate::CChecksItem {
    unsafe {
        match (*iterator).item() {
            Some(item) => item.ptr(),
            None => null(),
        }
    }
}

#[no_mangle]
pub extern "C" fn cchecks_item_iterator_is_done(iterator: *const CChecksItemsIterator) -> bool {
    unsafe {
        let iterator = &(*iterator);
        let items = &(*iterator.items);

        iterator.index >= items.length
    }
}
