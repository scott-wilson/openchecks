use std::ptr::{null, null_mut};

use crate::item::cchecks_item_clone;

/// The CChecksItems iterable container is used to iterate over any number of
/// and any sized objects.
#[repr(C)]
pub struct CChecksItems {
    /// The pointer to the check item array. Must be `item_size * length` in
    /// memory, or is invalid.
    pub ptr: *mut crate::CChecksItem,
    /// The size of an item in the array. Must be `sizeof(item)`, and not
    /// `sizeof(item_value)`. For example, if there's an `IntItem` container
    /// that represents integers, then `item_size == sizeof(IntItem)`.
    pub item_size: usize,
    /// The length of the array is the number of items in the array. If there's
    /// 5 items, then the length is 5.
    pub length: usize,
    /// The destroy function is responsible for freeing the pointer once the
    /// items have been destroyed. Trying to destroy the items in this function
    /// will cause double frees.
    pub destroy_fn: unsafe extern "C" fn(*mut crate::CChecksItem) -> (),
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

                for (index, item) in unsafe { cchecks_items_iterator_new(self) }.enumerate() {
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
            ptr,
            item_size: self.item_size,
            length: self.length,
            destroy_fn: destroy_cloned_items,
        }
    }
}

/// Create a new item container.
///
/// # Safety
///
/// The items pointer must be not null, and the size must be
/// `item_size * length` in bytes.
///
/// The destroy function must only free the items pointer. Trying to destroy the
/// items will cause a double free error.
#[no_mangle]
pub unsafe extern "C" fn cchecks_items_new(
    items: *mut crate::CChecksItem,
    item_size: usize,
    length: usize,
    destroy_fn: unsafe extern "C" fn(*mut crate::CChecksItem) -> (),
) -> CChecksItems {
    CChecksItems {
        ptr: items,
        item_size,
        length,
        destroy_fn,
    }
}

/// Create a new iterator to iterate over the items.
///
/// # Safety
///
/// The items pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_items_iterator_new(
    items: *const CChecksItems,
) -> CChecksItemsIterator {
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
                .add(self.index * (*self.items).item_size)
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

/// Return the pointer to the next item. A null pointer represents no more
/// items.
///
/// # Safety
///
/// The iterator pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_item_iterator_next(
    iterator: *mut CChecksItemsIterator,
) -> *const crate::CChecksItem {
    unsafe {
        match (*iterator).next() {
            Some(item) => item.ptr(),
            None => null(),
        }
    }
}

/// Return the pointer to the current item. A null pointer represents no more
/// items.
///
/// # Safety
///
/// The iterator pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_item_iterator_item(
    iterator: *mut CChecksItemsIterator,
) -> *const crate::CChecksItem {
    unsafe {
        match (*iterator).item() {
            Some(item) => item.ptr(),
            None => null(),
        }
    }
}

/// Return if the iterator has finished.
///
/// # Safety
///
/// The iterator pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_item_iterator_is_done(
    iterator: *const CChecksItemsIterator,
) -> bool {
    unsafe {
        let iterator = &(*iterator);
        let items = &(*iterator.items);

        iterator.index >= items.length
    }
}
