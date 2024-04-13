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
}

size_t int_items_length_fn(const CChecksItems *items) {
  return ((const IntItems *)items)->length;
}

size_t int_items_item_size_fn(const CChecksItems *items) {
  return sizeof(IntItem);
}

void int_items_destroy_fn(CChecksItems *items) { free(items); }

IntItems *create_int_items(size_t length) {
  IntItems *int_items = malloc(sizeof(IntItems));
  int_items->header.get_fn = int_items_get_fn;
  int_items->header.clone_fn = int_items_clone_fn;
  int_items->header.length_fn = int_items_length_fn;
  int_items->header.item_size_fn = int_items_item_size_fn;
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
