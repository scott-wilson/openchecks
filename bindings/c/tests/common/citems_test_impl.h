#ifndef cchecks_tests_citems
#define cchecks_tests_citems

#include "cchecks.h"

typedef struct IntItems {
  CChecksItems header;
  IntItem *values;
  size_t length;
} IntItems;

IntItems *create_int_items(size_t length);
void int_items_set(IntItems *items, size_t index, IntItem item);

const CChecksItem *int_items_get_fn(const CChecksItems *items, size_t index) {
  if (index < cchecks_items_length(items)) {
    return (const CChecksItem *)(&((const IntItems *)items)->values[index]);
  }
  { return NULL; }
}

CChecksItems *int_items_clone_fn(const CChecksItems *items) {
  const IntItems *int_items = ((const IntItems *)items);
  IntItems *new_int_items = create_int_items(int_items->length);

  for (size_t i = 0; i < cchecks_items_length(items); i++) {
    int_item_clone_in_place(&(int_items->values[i]),
                            &(new_int_items->values[i]));
  }

  return (CChecksItems *)new_int_items;
}

size_t int_items_length_fn(const CChecksItems *items) {
  return ((const IntItems *)items)->length;
}

size_t int_items_item_size_fn(const CChecksItems *items) {
  return sizeof(IntItem);
}

bool int_items_eq_fn(const struct CChecksItems *items,
                     const struct CChecksItems *other_items) {
  if (items == NULL && other_items == NULL) {
    return true;
  } else if (items == NULL && other_items != NULL) {
    return false;
  } else if (items != NULL && other_items == NULL) {
    return false;
  } else if (cchecks_items_length(items) != cchecks_items_length(other_items)) {
    return false;
  }

  for (size_t i = 0; i < cchecks_items_length(items); i++) {
    const struct CChecksItem *item = cchecks_items_get(items, i);
    const struct CChecksItem *other_item = cchecks_items_get(other_items, i);

    if (!cchecks_item_eq(item, other_item)) {
      return false;
    }
  }

  return true;
}

void int_items_destroy_fn(CChecksItems *items) { free(items); }

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

#endif // cchecks_tests_citems
