#ifndef openchecks_tests_citems
#define openchecks_tests_citems

#include "openchecks.h"

typedef struct IntItems {
  OpenChecksItems header;
  IntItem *values;
  size_t length;
} IntItems;

IntItems *create_int_items(size_t length);
void int_items_set(IntItems *items, size_t index, IntItem item);

const OpenChecksItem *int_items_get_fn(const OpenChecksItems *items,
                                       size_t index) {
  if (index < openchecks_items_length(items)) {
    return (const OpenChecksItem *)(&((const IntItems *)items)->values[index]);
  }
  { return NULL; }
}

OpenChecksItems *int_items_clone_fn(const OpenChecksItems *items) {
  const IntItems *int_items = ((const IntItems *)items);
  IntItems *new_int_items = create_int_items(int_items->length);

  for (size_t i = 0; i < openchecks_items_length(items); i++) {
    int_item_clone_in_place(&(int_items->values[i]),
                            &(new_int_items->values[i]));
  }

  return (OpenChecksItems *)new_int_items;
}

size_t int_items_length_fn(const OpenChecksItems *items) {
  return ((const IntItems *)items)->length;
}

size_t int_items_item_size_fn(const OpenChecksItems *items) {
  (void)items; // Ignoring because the item size is fixed.
  return sizeof(IntItem);
}

bool int_items_eq_fn(const struct OpenChecksItems *items,
                     const struct OpenChecksItems *other_items) {
  if (items == NULL && other_items == NULL) {
    return true;
  } else if (items == NULL && other_items != NULL) {
    return false;
  } else if (items != NULL && other_items == NULL) {
    return false;
  } else if (openchecks_items_length(items) !=
             openchecks_items_length(other_items)) {
    return false;
  }

  for (size_t i = 0; i < openchecks_items_length(items); i++) {
    const struct OpenChecksItem *item = openchecks_items_get(items, i);
    const struct OpenChecksItem *other_item =
        openchecks_items_get(other_items, i);

    if (!openchecks_item_eq(item, other_item)) {
      return false;
    }
  }

  return true;
}

void int_items_destroy_fn(OpenChecksItems *items) { free(items); }

IntItems *create_int_items(size_t length) {
  IntItems *int_items = malloc(sizeof(IntItems));
  int_items->header.get_fn = int_items_get_fn;
  int_items->header.clone_fn = int_items_clone_fn;
  int_items->header.length_fn = int_items_length_fn;
  int_items->header.item_size_fn = int_items_item_size_fn;
  int_items->header.eq_fn = int_items_eq_fn;
  int_items->header.destroy_fn = int_items_destroy_fn;

  int_items->values = malloc(length * sizeof(IntItem));
  int_items->length = length;

  return int_items;
}

void int_items_set(IntItems *items, size_t index, IntItem item) {
  if (index < items->length) {
    items->values[index] = item;
  }
}

#endif // openchecks_tests_citems
