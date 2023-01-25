#include <float.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "cchecks.h"
#include "citem_test_impl.h"
#include "citems_test_impl.h"

/* ----------------------------------------------------------------------------
  Checks
*/
static void test_cchecks_check_result_new(void **state) {
  CChecksStatus status = CChecksStatusPassed;
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItem *items = malloc(item_size * item_count);

  for (size_t i = 0; i < item_count; i++) {
    items[i] = create_int_item(i, NULL);
  }

  bool can_fix = false;
  bool can_skip = false;
  char *error = NULL;

  CChecksCheckResult result = cchecks_check_result_new(
      status, message, (CChecksItem *)items, item_size, item_count, can_fix,
      can_skip, error, int_items_destroy_fn);

  // Status
  assert_int_equal(cchecks_check_result_status(&result), status);
  // Message
  CChecksStringView result_message = cchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  CChecksItems const *result_items = cchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(result_items->length, item_count);
  assert_int_equal(result_items->item_size, item_size);

  CChecksItemsIterator items_iter = cchecks_items_iterator_new(result_items);
  size_t index = 0;
  CChecksItem const *item;

  for (; !cchecks_item_iterator_is_done(&items_iter);
       cchecks_item_iterator_next(&items_iter)) {
    item = cchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)cchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(cchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(cchecks_check_result_can_skip(&result), can_skip);

  // Error
  CChecksStringView result_error = cchecks_check_result_error(&result);
  assert_string_equal(result_error.string, "");

  // Cleanup
  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_passed(void **state) {
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItem *items = malloc(item_size * item_count);

  for (size_t i = 0; i < item_count; i++) {
    items[i] = create_int_item(i, NULL);
  }

  bool can_fix = false;
  bool can_skip = false;

  CChecksCheckResult result = cchecks_check_result_passed(
      message, (CChecksItem *)items, item_size, item_count, can_fix, can_skip,
      int_items_destroy_fn);

  // Status
  assert_int_equal(cchecks_check_result_status(&result), CChecksStatusPassed);
  // Message
  CChecksStringView result_message = cchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  CChecksItems const *result_items = cchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(result_items->length, item_count);
  assert_int_equal(result_items->item_size, item_size);

  CChecksItemsIterator items_iter = cchecks_items_iterator_new(result_items);
  size_t index = 0;
  CChecksItem const *item;

  for (; !cchecks_item_iterator_is_done(&items_iter);
       cchecks_item_iterator_next(&items_iter)) {
    item = cchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)cchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(cchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(cchecks_check_result_can_skip(&result), can_skip);

  // Cleanup
  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_skipped(void **state) {
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItem *items = malloc(item_size * item_count);

  for (size_t i = 0; i < item_count; i++) {
    items[i] = create_int_item(i, NULL);
  }

  bool can_fix = false;
  bool can_skip = false;

  CChecksCheckResult result = cchecks_check_result_skipped(
      message, (CChecksItem *)items, item_size, item_count, can_fix, can_skip,
      int_items_destroy_fn);

  // Status
  assert_int_equal(cchecks_check_result_status(&result), CChecksStatusSkipped);
  // Message
  CChecksStringView result_message = cchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  CChecksItems const *result_items = cchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(result_items->length, item_count);
  assert_int_equal(result_items->item_size, item_size);

  CChecksItemsIterator items_iter = cchecks_items_iterator_new(result_items);
  size_t index = 0;
  CChecksItem const *item;

  for (; !cchecks_item_iterator_is_done(&items_iter);
       cchecks_item_iterator_next(&items_iter)) {
    item = cchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)cchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(cchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(cchecks_check_result_can_skip(&result), can_skip);

  // Cleanup
  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_warning(void **state) {
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItem *items = malloc(item_size * item_count);

  for (size_t i = 0; i < item_count; i++) {
    items[i] = create_int_item(i, NULL);
  }

  bool can_fix = false;
  bool can_skip = false;

  CChecksCheckResult result = cchecks_check_result_warning(
      message, (CChecksItem *)items, item_size, item_count, can_fix, can_skip,
      int_items_destroy_fn);

  // Status
  assert_int_equal(cchecks_check_result_status(&result), CChecksStatusWarning);
  // Message
  CChecksStringView result_message = cchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  CChecksItems const *result_items = cchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(result_items->length, item_count);
  assert_int_equal(result_items->item_size, item_size);

  CChecksItemsIterator items_iter = cchecks_items_iterator_new(result_items);
  size_t index = 0;
  CChecksItem const *item;

  for (; !cchecks_item_iterator_is_done(&items_iter);
       cchecks_item_iterator_next(&items_iter)) {
    item = cchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)cchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(cchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(cchecks_check_result_can_skip(&result), can_skip);

  // Cleanup
  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_failed(void **state) {
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItem *items = malloc(item_size * item_count);

  for (size_t i = 0; i < item_count; i++) {
    items[i] = create_int_item(i, NULL);
  }

  bool can_fix = false;
  bool can_skip = false;

  CChecksCheckResult result = cchecks_check_result_failed(
      message, (CChecksItem *)items, item_size, item_count, can_fix, can_skip,
      int_items_destroy_fn);

  // Status
  assert_int_equal(cchecks_check_result_status(&result), CChecksStatusFailed);
  // Message
  CChecksStringView result_message = cchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  CChecksItems const *result_items = cchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(result_items->length, item_count);
  assert_int_equal(result_items->item_size, item_size);

  CChecksItemsIterator items_iter = cchecks_items_iterator_new(result_items);
  size_t index = 0;
  CChecksItem const *item;

  for (; !cchecks_item_iterator_is_done(&items_iter);
       cchecks_item_iterator_next(&items_iter)) {
    item = cchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)cchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(cchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(cchecks_check_result_can_skip(&result), can_skip);

  // Cleanup
  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_destroy(void **state) {
  CChecksStatus status;
  char *message;
  size_t item_count;
  size_t item_size;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  CChecksCheckResult result;

  // All pointers null.
  status = CChecksStatusPassed;
  message = NULL;
  item_count = 0;
  item_size = 0;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                    item_size, item_count, can_fix, can_skip,
                                    error, int_items_destroy_fn);
  cchecks_check_result_destroy(&result);

  // No pointers null.
  status = CChecksStatusPassed;
  message = "test";
  item_count = 5;
  item_size = sizeof(IntItem);
  items = malloc(item_size * item_count);
  can_fix = false;
  can_skip = false;
  error = "test";

  for (size_t i = 0; i < item_count; i++) {
    items[i] = create_int_item(i, NULL);
  }

  result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                    item_size, item_count, can_fix, can_skip,
                                    error, int_items_destroy_fn);
  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_status(void **state) {
  CChecksStatus status;
  char *message;
  size_t item_count;
  size_t item_size;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  CChecksCheckResult result;

  CChecksStatus statuses[] = {
      CChecksStatusPending, CChecksStatusSkipped, CChecksStatusPassed,
      CChecksStatusWarning, CChecksStatusFailed,  CChecksStatusSystemError,
  };

  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    item_count = 0;
    item_size = 0;
    items = NULL;
    can_fix = false;
    can_skip = false;
    error = NULL;
    result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                      item_size, item_count, can_fix, can_skip,
                                      error, int_items_destroy_fn);
    assert_int_equal(cchecks_check_result_status(&result), status);
    cchecks_check_result_destroy(&result);
  }
}

static void test_cchecks_check_result_message(void **state) {
  CChecksStatus status;
  char *message;
  size_t item_count;
  size_t item_size;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  CChecksCheckResult result;
  CChecksStringView msg;

  // Null message.
  status = CChecksStatusPassed;
  message = NULL;
  item_count = 0;
  item_size = 0;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                    item_size, item_count, can_fix, can_skip,
                                    error, int_items_destroy_fn);
  msg = cchecks_check_result_message(&result);
  assert_string_equal(msg.string, "");
  cchecks_check_result_destroy(&result);

  // Non-null message.
  status = CChecksStatusPassed;
  message = "test";
  item_count = 0;
  item_size = 0;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                    item_size, item_count, can_fix, can_skip,
                                    error, int_items_destroy_fn);
  msg = cchecks_check_result_message(&result);
  assert_string_equal(msg.string, "test");
  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_items(void **state) {
  CChecksStatus status;
  char *message;
  size_t item_count;
  size_t item_size;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  CChecksCheckResult result;
  CChecksItems const *result_items;
  CChecksItemsIterator items_iter;
  CChecksItem const *item;

  // Null items.
  status = CChecksStatusPassed;
  message = NULL;
  item_count = 0;
  item_size = 0;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                    item_size, item_count, can_fix, can_skip,
                                    error, int_items_destroy_fn);
  result_items = cchecks_check_result_items(&result);
  assert_null(result_items);

  items_iter = cchecks_items_iterator_new(result_items);
  assert_int_equal(items_iter.index, 0);
  assert_ptr_equal(items_iter.items, result_items);
  assert_null(items_iter.items);

  cchecks_check_result_destroy(&result);

  // 0 items.
  status = CChecksStatusPassed;
  message = NULL;
  item_count = 0;
  item_size = sizeof(IntItem);
  items = malloc(item_size * item_count);
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                    item_size, item_count, can_fix, can_skip,
                                    error, int_items_destroy_fn);
  result_items = cchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(result_items->item_size, item_size);
  assert_int_equal(result_items->length, item_count);
  assert_non_null(result_items->ptr);

  items_iter = cchecks_items_iterator_new(result_items);
  assert_int_equal(items_iter.index, 0);
  assert_ptr_equal(items_iter.items, result_items);
  assert_non_null(items_iter.items);

  assert_true(cchecks_item_iterator_is_done(&items_iter));
  assert_null(cchecks_item_iterator_item(&items_iter));
  assert_null(cchecks_item_iterator_next(&items_iter));

  cchecks_check_result_destroy(&result);

  // 1 item.
  status = CChecksStatusPassed;
  message = NULL;
  item_count = 1;
  item_size = sizeof(IntItem);
  items = malloc(item_size * item_count);
  can_fix = false;
  can_skip = false;
  error = NULL;

  items[0] = create_int_item(1, NULL);

  result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                    item_size, item_count, can_fix, can_skip,
                                    error, int_items_destroy_fn);
  result_items = cchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(result_items->item_size, item_size);
  assert_int_equal(result_items->length, item_count);
  assert_non_null(result_items->ptr);

  items_iter = cchecks_items_iterator_new(result_items);
  assert_int_equal(items_iter.index, 0);
  assert_ptr_equal(items_iter.items, result_items);
  assert_non_null(items_iter.items);

  assert_false(cchecks_item_iterator_is_done(&items_iter));
  item = cchecks_item_iterator_item(&items_iter);
  assert_non_null(item);
  assert_int_equal(*(int *)cchecks_item_value(item), 1);
  item = cchecks_item_iterator_next(&items_iter);
  assert_true(cchecks_item_iterator_is_done(&items_iter));
  assert_int_equal(items_iter.index, 1);
  assert_non_null(item);
  assert_int_equal(*(int *)cchecks_item_value(item), 1);
  item = cchecks_item_iterator_item(&items_iter);
  assert_null(item);

  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_can_fix(void **state) {
  CChecksStatus status;
  char *message;
  size_t item_count;
  size_t item_size;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  CChecksCheckResult result;

  CChecksStatus statuses[] = {
      CChecksStatusPending, CChecksStatusSkipped, CChecksStatusPassed,
      CChecksStatusWarning, CChecksStatusFailed,  CChecksStatusSystemError,
  };

  // can_fix = true.
  bool expected[] = {true, true, true, true, true, false};

  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    item_count = 0;
    item_size = 0;
    items = NULL;
    can_fix = true;
    can_skip = false;
    error = NULL;

    result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                      item_size, item_count, can_fix, can_skip,
                                      error, int_items_destroy_fn);

    assert_int_equal(cchecks_check_result_can_fix(&result), expected[i]);
    cchecks_check_result_destroy(&result);
  }

  // can_fix = false.
  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    item_count = 0;
    item_size = 0;
    items = NULL;
    can_fix = false;
    can_skip = false;
    error = NULL;

    result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                      item_size, item_count, can_fix, can_skip,
                                      error, int_items_destroy_fn);

    assert_int_equal(cchecks_check_result_can_fix(&result), false);
    cchecks_check_result_destroy(&result);
  }
}

static void test_cchecks_check_result_can_skip(void **state) {
  CChecksStatus status;
  char *message;
  size_t item_count;
  size_t item_size;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  CChecksCheckResult result;

  CChecksStatus statuses[] = {
      CChecksStatusPending, CChecksStatusSkipped, CChecksStatusPassed,
      CChecksStatusWarning, CChecksStatusFailed,  CChecksStatusSystemError,
  };

  // can_fix = true.
  bool expected[] = {true, true, true, true, true, false};

  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    item_count = 0;
    item_size = 0;
    items = NULL;
    can_fix = false;
    can_skip = true;
    error = NULL;

    result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                      item_size, item_count, can_fix, can_skip,
                                      error, int_items_destroy_fn);

    assert_int_equal(cchecks_check_result_can_skip(&result), expected[i]);
    cchecks_check_result_destroy(&result);
  }

  // can_fix = false.
  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    item_count = 0;
    item_size = 0;
    items = NULL;
    can_fix = false;
    can_skip = false;
    error = NULL;

    result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                      item_size, item_count, can_fix, can_skip,
                                      error, int_items_destroy_fn);

    assert_int_equal(cchecks_check_result_can_skip(&result), false);
    cchecks_check_result_destroy(&result);
  }
}

static void test_cchecks_check_result_error(void **state) {
  CChecksStatus status;
  char *message;
  size_t item_count;
  size_t item_size;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  CChecksCheckResult result;
  CChecksStringView msg;

  // Null error.
  status = CChecksStatusPassed;
  message = NULL;
  item_count = 0;
  item_size = 0;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                    item_size, item_count, can_fix, can_skip,
                                    error, int_items_destroy_fn);
  msg = cchecks_check_result_error(&result);
  assert_string_equal(msg.string, "");
  cchecks_check_result_destroy(&result);

  // Non-null message.
  status = CChecksStatusPassed;
  message = NULL;
  item_count = 0;
  item_size = 0;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = "error";

  result = cchecks_check_result_new(status, message, (CChecksItem *)items,
                                    item_size, item_count, can_fix, can_skip,
                                    error, int_items_destroy_fn);
  msg = cchecks_check_result_error(&result);
  assert_string_equal(msg.string, "error");
  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_check_duration(void **state) {
  CChecksStatus status = CChecksStatusPassed;
  char *message = NULL;
  size_t item_count = 0;
  size_t item_size = 0;
  IntItem *items = NULL;

  bool can_fix = false;
  bool can_skip = false;
  char *error = NULL;

  CChecksCheckResult result = cchecks_check_result_new(
      status, message, (CChecksItem *)items, item_size, item_count, can_fix,
      can_skip, error, int_items_destroy_fn);

  assert_double_equal(cchecks_check_result_check_duration(&result), 0.0,
                      DBL_EPSILON);

  cchecks_check_result_destroy(&result);
}

static void test_cchecks_check_result_fix_duration(void **state) {
  CChecksStatus status = CChecksStatusPassed;
  char *message = NULL;
  size_t item_count = 0;
  size_t item_size = 0;
  IntItem *items = NULL;

  bool can_fix = false;
  bool can_skip = false;
  char *error = NULL;

  CChecksCheckResult result = cchecks_check_result_new(
      status, message, (CChecksItem *)items, item_size, item_count, can_fix,
      can_skip, error, int_items_destroy_fn);

  assert_double_equal(cchecks_check_result_fix_duration(&result), 0.0,
                      DBL_EPSILON);

  cchecks_check_result_destroy(&result);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_cchecks_check_result_new),
      cmocka_unit_test(test_cchecks_check_result_passed),
      cmocka_unit_test(test_cchecks_check_result_new),
      cmocka_unit_test(test_cchecks_check_result_passed),
      cmocka_unit_test(test_cchecks_check_result_skipped),
      cmocka_unit_test(test_cchecks_check_result_warning),
      cmocka_unit_test(test_cchecks_check_result_failed),
      cmocka_unit_test(test_cchecks_check_result_destroy),
      cmocka_unit_test(test_cchecks_check_result_message),
      cmocka_unit_test(test_cchecks_check_result_items),
      cmocka_unit_test(test_cchecks_check_result_can_fix),
      cmocka_unit_test(test_cchecks_check_result_can_skip),
      cmocka_unit_test(test_cchecks_check_result_check_duration),
      cmocka_unit_test(test_cchecks_check_result_fix_duration),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
