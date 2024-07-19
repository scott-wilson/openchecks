use std::ptr::null;

/// The OpenChecksItems iterable container is used to iterate over any number of
/// and any sized objects.
#[repr(C)]
pub struct OpenChecksItems {
    /// Get an item from the container.
    ///
    /// # Safety
    ///
    /// The container pointer must not be null. Passing an invalid index will
    /// return a null pointer.
    pub get_fn: unsafe extern "C" fn(*const Self, usize) -> *const crate::OpenChecksItem,
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
    /// The compare function is used to compare containers.
    ///
    /// # Safety
    ///
    /// This must support comparing a null with another null or non-null value.
    /// Null == null is true, but null != non-null is false.
    pub eq_fn: unsafe extern "C" fn(*const Self, *const Self) -> bool,
    /// Destroy the container.
    ///
    /// # Safety
    ///
    /// The container pointer must not be null.
    pub destroy_fn: unsafe extern "C" fn(*mut Self),
}

impl Drop for OpenChecksItems {
    fn drop(&mut self) {
        unsafe { (self.destroy_fn)(self) }
    }
}

impl std::iter::IntoIterator for OpenChecksItems {
    type Item = crate::item::ChecksItemWrapper;
    type IntoIter = OpenChecksItemsIterator;

    fn into_iter(self) -> Self::IntoIter {
        OpenChecksItemsIterator::new(&self)
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
pub unsafe extern "C" fn openchecks_items_get(
    items: *const OpenChecksItems,
    index: usize,
) -> *const crate::OpenChecksItem {
    ((*items).get_fn)(items, index)
}

/// Clone the items.
///
/// # Safety
///
/// The items pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_items_clone(
    items: *const OpenChecksItems,
) -> *mut OpenChecksItems {
    ((*items).clone_fn)(items)
}

/// Get the length of the items.
///
/// # Safety
///
/// The items pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_items_length(items: *const OpenChecksItems) -> usize {
    ((*items).length_fn)(items)
}

/// Get the size of each item in the items. All items must be the same size.
///
/// # Safety
///
/// The items pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_items_item_size(items: *const OpenChecksItems) -> usize {
    ((*items).item_size_fn)(items)
}

/// Compare two items containers for equality.
///
/// # Safety
///
/// The items pointer and the other items pointer can be null. If both are null,
/// then this will return true. If one is null and the other is not, then this
/// will return false.
#[no_mangle]
pub unsafe extern "C" fn openchecks_items_eq(
    items: *const OpenChecksItems,
    other_items: *const OpenChecksItems,
) -> bool {
    if items.is_null() && other_items.is_null() {
        true
    } else if items.is_null() && !other_items.is_null() {
        false
    } else if !items.is_null() && other_items.is_null() {
        false
    } else {
        ((*items).eq_fn)(items, other_items)
    }
}

#[no_mangle]
pub unsafe extern "C" fn openchecks_items_destroy(items: *mut OpenChecksItems) {
    ((*items).destroy_fn)(items)
}

/// Create a new iterator to iterate over the items.
///
/// # Safety
///
/// The items pointer must not be null.
#[no_mangle]
pub unsafe extern "C" fn openchecks_items_iterator_new(
    items: *const OpenChecksItems,
) -> OpenChecksItemsIterator {
    OpenChecksItemsIterator { items, index: 0 }
}

#[repr(C)]
pub struct OpenChecksItemsIterator {
    pub items: *const OpenChecksItems,
    pub index: usize,
}

impl OpenChecksItemsIterator {
    pub(crate) fn item(&self) -> Option<<Self as Iterator>::Item> {
        unsafe {
            if self.index >= openchecks_items_length(self.items) {
                return None;
            }

            let result = openchecks_items_get(self.items, self.index);
            Some(crate::item::ChecksItemWrapper::new(result))
        }
    }
}

impl Iterator for OpenChecksItemsIterator {
    type Item = crate::item::ChecksItemWrapper;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.item();
        self.index += 1;

        item
    }
}

impl OpenChecksItemsIterator {
    fn new(items: *const OpenChecksItems) -> Self {
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
pub unsafe extern "C" fn openchecks_item_iterator_next(
    iterator: *mut OpenChecksItemsIterator,
) -> *const crate::OpenChecksItem {
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
pub unsafe extern "C" fn openchecks_item_iterator_item(
    iterator: *mut OpenChecksItemsIterator,
) -> *const crate::OpenChecksItem {
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
pub unsafe extern "C" fn openchecks_item_iterator_is_done(
    iterator: *const OpenChecksItemsIterator,
) -> bool {
    unsafe {
        let iterator = &(*iterator);

        iterator.index >= openchecks_items_length(iterator.items)
    }
}

pub struct OpenChecksItemsWrapper {
    pub ptr: *mut OpenChecksItems,
}

impl std::iter::IntoIterator for OpenChecksItemsWrapper {
    type Item = crate::item::ChecksItemWrapper;
    type IntoIter = OpenChecksItemsIterator;

    fn into_iter(self) -> Self::IntoIter {
        OpenChecksItemsIterator::new(self.ptr)
    }
}
