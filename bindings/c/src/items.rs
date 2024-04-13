use std::ptr::null;
/// The CChecksItems iterable container is used to iterate over any number of
/// and any sized objects.
#[repr(C)]
pub struct CChecksItems {
    /// Get an item from the container.
    ///
    /// # Safety
    ///
    /// The container pointer must not be null. Passing an invalid index will
    /// return a null pointer.
    pub get_fn: unsafe extern "C" fn(*const Self, usize) -> *const crate::CChecksItem,
    /// Clone the container.
    ///
    /// # Safety
    ///
    /// The container pointer must not be null.
    pub clone_fn: unsafe extern "C" fn(*const Self) -> *mut Self,
    /// Get the length of the container.
    ///
    /// # Safety
    ///
    /// The container pointer must not be null.
    pub length_fn: unsafe extern "C" fn(*const Self) -> usize,
    /// Get the size of each item in the container. This must be the same for
    /// all items in the container.
    ///
    /// # Safety
    ///
    /// The container pointer must not be null.
    pub item_size_fn: unsafe extern "C" fn(*const Self) -> usize,
    /// Destroy the container.
    ///
    /// # Safety
    ///
    /// The container pointer must not be null.
    pub destroy_fn: unsafe extern "C" fn(*mut Self),
}

impl Drop for CChecksItems {
    fn drop(&mut self) {
        unsafe { (self.destroy_fn)(self) }
    }
}

impl std::iter::IntoIterator for CChecksItems {
    type Item = crate::item::ChecksItemWrapper;
    type IntoIter = CChecksItemsIterator;

    fn into_iter(self) -> Self::IntoIter {
        CChecksItemsIterator::new(&self)
    }
}

/// Get an item from the container.
///
/// A null pointer is returned if the index is invalid.
///
/// # Safety
///
/// The items pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_items_get(
    items: *const CChecksItems,
    index: usize,
) -> *const crate::CChecksItem {
    ((*items).get_fn)(items, index)
}

/// Clone the items.
///
/// # Safety
///
/// The items pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_items_clone(items: *const CChecksItems) -> *mut CChecksItems {
    ((*items).clone_fn)(items)
}

/// Get the length of the items.
///
/// # Safety
///
/// The items pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_items_length(items: *const CChecksItems) -> usize {
    ((*items).length_fn)(items)
}

/// Get the size of each item in the items. All items must be the same size.
///
/// # Safety
///
/// The items pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn cchecks_items_item_size(items: *const CChecksItems) -> usize {
    ((*items).item_size_fn)(items)
}

/// Compare two items containers for equality.
///
/// # Safety
///
/// The items pointer and the other items pointer must not be null, otherwise
/// this will panic.
#[no_mangle]
pub unsafe extern "C" fn cchecks_items_eq(
    items: *const CChecksItems,
    other_items: *const CChecksItems,
) -> bool {
    if items.is_null() {
        panic!("items pointer is null");
    } else if other_items.is_null() {
        panic!("other_items pointer is null");
    }

    if cchecks_items_length(items) != cchecks_items_length(other_items) {
        return false;
    } else if cchecks_items_item_size(items) != cchecks_items_item_size(other_items) {
        return false;
    } else {
        for index in 0..cchecks_items_length(items) {
            let item = cchecks_items_get(items, index);
            let other_item = cchecks_items_get(other_items, index);

            if !crate::item::cchecks_item_eq(item, other_item) {
                return false;
            }
        }
    }

    true
}

#[no_mangle]
pub unsafe extern "C" fn cchecks_items_destroy(items: *mut CChecksItems) {
    ((*items).destroy_fn)(items)
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
            if self.index >= cchecks_items_length(self.items) {
                return None;
            }

            let result = cchecks_items_get(self.items, self.index);
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

        iterator.index >= cchecks_items_length(iterator.items)
    }
}

pub struct CChecksItemsWrapper {
    pub ptr: *mut CChecksItems,
}

impl std::iter::IntoIterator for CChecksItemsWrapper {
    type Item = crate::item::ChecksItemWrapper;
    type IntoIter = CChecksItemsIterator;

    fn into_iter(self) -> Self::IntoIter {
        CChecksItemsIterator::new(self.ptr)
    }
}
