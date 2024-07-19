#pragma once

#include <iostream>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include <openchecks.h>
}

const std::string_view PRINTABLE_CHARS =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*"
    "+,-./:;<=>?@[\\]^_`{|}~ \t\n\r";

/* ----------------------------------------------------------------------------
  Int Item
*/
struct IntItem {
  OpenChecksItem header;
  std::string type_hint;
  int value;
  bool has_type_hint;
};

void destroy_string_ptr(OpenChecksString *string) {
  if (string->string != NULL) {
    free((void *)string->string);
  }
}

void int_item_clone_in_place(const IntItem *item, IntItem *new_item) {
  new_item->header.type_hint_fn = item->header.type_hint_fn;
  new_item->header.value_fn = item->header.value_fn;
  new_item->header.clone_fn = item->header.clone_fn;
  new_item->header.destroy_fn = item->header.destroy_fn;
  new_item->header.debug_fn = item->header.debug_fn;
  new_item->header.display_fn = item->header.display_fn;
  new_item->header.lt_fn = item->header.lt_fn;
  new_item->header.eq_fn = item->header.eq_fn;

  new_item->type_hint = item->type_hint;
  new_item->value = item->value;
  new_item->has_type_hint = item->has_type_hint;
}

const char *int_item_type_hint_fn(const OpenChecksItem *item) {
  if (((IntItem *)item)->has_type_hint) {
    return ((IntItem *)item)->type_hint.c_str();
  } else {
    return nullptr;
  }
}

const void *int_item_value_fn(const OpenChecksItem *item) {
  return (void *)(&((IntItem *)item)->value);
}

OpenChecksItem *int_item_clone_fn(const OpenChecksItem *item) {
  IntItem *old_item = (IntItem *)item;
  IntItem *new_int_item = new IntItem();
  int_item_clone_in_place(old_item, new_int_item);

  return (OpenChecksItem *)new_int_item;
}

void int_item_destroy_fn(OpenChecksItem *item) { delete ((IntItem *)item); }

OpenChecksString int_item_debug_fn(const OpenChecksItem *item) {
  return item->display_fn(item);
}

OpenChecksString int_item_display_fn(const OpenChecksItem *item) {
  int value = ((IntItem *)item)->value;
  size_t length = snprintf(NULL, 0, "%d", value);
  char *display_string = (char *)malloc(length + 1);
  sprintf(display_string, "%d", value);

  OpenChecksString result;
  result.string = display_string;
  result.destroy_fn = destroy_string_ptr;

  return result;
}

bool int_item_lt_fn(const OpenChecksItem *item,
                    const OpenChecksItem *other_item) {
  return ((IntItem *)item)->value < ((IntItem *)other_item)->value;
}

bool int_item_eq_fn(const OpenChecksItem *item,
                    const OpenChecksItem *other_item) {
  return ((IntItem *)item)->value == ((IntItem *)other_item)->value;
}

IntItem create_int_item(FuzzedDataProvider &provider) {
  IntItem item;
  item.header.type_hint_fn = int_item_type_hint_fn;
  item.header.value_fn = int_item_value_fn;
  item.header.clone_fn = int_item_clone_fn;
  item.header.destroy_fn = int_item_destroy_fn;
  item.header.debug_fn = int_item_debug_fn;
  item.header.display_fn = int_item_display_fn;
  item.header.lt_fn = int_item_lt_fn;
  item.header.eq_fn = int_item_eq_fn;
  item.has_type_hint = provider.ConsumeBool();
  item.value = provider.ConsumeIntegral<int>();

  if (item.has_type_hint) {
    item.type_hint = provider.ConsumeRandomLengthString();
  } else {
    item.type_hint = std::string("");
  }

  return item;
}

std::string get_message(FuzzedDataProvider &provider) {
  std::string message = provider.ConsumeRandomLengthString();

  for (size_t i = 0; i < message.size(); i++) {
    message[i] = PRINTABLE_CHARS[message[i] % PRINTABLE_CHARS.size()];
  }

  return message;
}

typedef struct IntItems {
  OpenChecksItems header;
  std::vector<IntItem> values;
} IntItems;

IntItems *create_int_items(size_t length);

const OpenChecksItem *int_items_get_fn(const OpenChecksItems *items,
                                       size_t index) {
  if (index < openchecks_items_length(items)) {
    return (const OpenChecksItem *)(&((const IntItems *)items)->values[index]);
  }
  { return NULL; }
}

OpenChecksItems *int_items_clone_fn(const OpenChecksItems *items) {
  const IntItems *int_items = ((const IntItems *)items);
  IntItems *new_int_items = create_int_items(int_items->values.size());

  new_int_items->values = int_items->values;

  return (OpenChecksItems *)new_int_items;
}

size_t int_items_length_fn(const OpenChecksItems *items) {
  return ((const IntItems *)items)->values.size();
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

void int_items_destroy_fn(OpenChecksItems *items) {
  delete ((IntItems *)items);
}

IntItems *create_int_items(size_t length) {
  IntItems *int_items = new IntItems();
  int_items->header.get_fn = int_items_get_fn;
  int_items->header.clone_fn = int_items_clone_fn;
  int_items->header.length_fn = int_items_length_fn;
  int_items->header.item_size_fn = int_items_item_size_fn;
  int_items->header.eq_fn = int_items_eq_fn;
  int_items->header.destroy_fn = int_items_destroy_fn;

  int_items->values = std::vector<IntItem>();
  int_items->values.reserve(length);

  return int_items;
}

IntItems *create_int_items(FuzzedDataProvider &provider) {
  size_t item_count = provider.ConsumeIntegralInRange<size_t>(0, 10);
  IntItems *items = create_int_items(item_count);

  for (size_t i = 0; i < item_count; i++) {
    items->values.push_back(create_int_item(provider));
  }

  return items;
}
