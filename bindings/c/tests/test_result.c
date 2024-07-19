#include <float.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "citem_test_impl.h"
#include "citems_test_impl.h"
#include "openchecks.h"

/* ----------------------------------------------------------------------------
  Checks
*/
static void test_openchecks_check_result_new(void **state) {
  (void)state;
  OpenChecksStatus status = OpenChecksStatusPassed;
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItems *items = create_int_items(item_count);

  for (size_t i = 0; i < item_count; i++) {
    IntItem item = create_int_item((int)i, NULL);
    int_items_set(items, i, item);
  }

  bool can_fix = false;
  bool can_skip = false;
  char *error = NULL;

  OpenChecksCheckResult result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);

  // Status
  assert_int_equal(openchecks_check_result_status(&result), status);
  // Message
  OpenChecksStringView result_message =
      openchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  OpenChecksItems const *result_items = openchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(openchecks_items_length(result_items), item_count);
  assert_int_equal(openchecks_items_item_size(result_items), item_size);

  OpenChecksItemsIterator items_iter =
      openchecks_items_iterator_new(result_items);
  size_t index = 0;
  OpenChecksItem const *item;

  for (; !openchecks_item_iterator_is_done(&items_iter);
       openchecks_item_iterator_next(&items_iter)) {
    item = openchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)openchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(openchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(openchecks_check_result_can_skip(&result), can_skip);

  // Error
  const char *result_error = openchecks_check_result_error(&result);
  assert_null(result_error);

  // Cleanup
  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_passed(void **state) {
  (void)state;
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItems *items = create_int_items(item_count);

  for (size_t i = 0; i < item_count; i++) {
    IntItem item = create_int_item((int)i, NULL);
    int_items_set(items, i, item);
  }

  bool can_fix = false;
  bool can_skip = false;

  OpenChecksCheckResult result = openchecks_check_result_passed(
      message, (OpenChecksItems *)items, can_fix, can_skip);

  // Status
  assert_int_equal(openchecks_check_result_status(&result),
                   OpenChecksStatusPassed);
  // Message
  OpenChecksStringView result_message =
      openchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  OpenChecksItems const *result_items = openchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(openchecks_items_length(result_items), item_count);
  assert_int_equal(openchecks_items_item_size(result_items), item_size);

  OpenChecksItemsIterator items_iter =
      openchecks_items_iterator_new(result_items);
  size_t index = 0;
  OpenChecksItem const *item;

  for (; !openchecks_item_iterator_is_done(&items_iter);
       openchecks_item_iterator_next(&items_iter)) {
    item = openchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)openchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(openchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(openchecks_check_result_can_skip(&result), can_skip);

  // Cleanup
  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_skipped(void **state) {
  (void)state;
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItems *items = create_int_items(item_count);

  for (size_t i = 0; i < item_count; i++) {
    IntItem item = create_int_item((int)i, NULL);
    int_items_set(items, i, item);
  }

  bool can_fix = false;
  bool can_skip = false;

  OpenChecksCheckResult result = openchecks_check_result_skipped(
      message, (OpenChecksItems *)items, can_fix, can_skip);

  // Status
  assert_int_equal(openchecks_check_result_status(&result),
                   OpenChecksStatusSkipped);
  // Message
  OpenChecksStringView result_message =
      openchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  OpenChecksItems const *result_items = openchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(openchecks_items_length(result_items), item_count);
  assert_int_equal(openchecks_items_item_size(result_items), item_size);

  OpenChecksItemsIterator items_iter =
      openchecks_items_iterator_new(result_items);
  size_t index = 0;
  OpenChecksItem const *item;

  for (; !openchecks_item_iterator_is_done(&items_iter);
       openchecks_item_iterator_next(&items_iter)) {
    item = openchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)openchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(openchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(openchecks_check_result_can_skip(&result), can_skip);

  // Cleanup
  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_warning(void **state) {
  (void)state;
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItems *items = create_int_items(item_count);

  for (size_t i = 0; i < item_count; i++) {
    IntItem item = create_int_item((int)i, NULL);
    int_items_set(items, i, item);
  }

  bool can_fix = false;
  bool can_skip = false;

  OpenChecksCheckResult result = openchecks_check_result_warning(
      message, (OpenChecksItems *)items, can_fix, can_skip);

  // Status
  assert_int_equal(openchecks_check_result_status(&result),
                   OpenChecksStatusWarning);
  // Message
  OpenChecksStringView result_message =
      openchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  OpenChecksItems const *result_items = openchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(openchecks_items_length(result_items), item_count);
  assert_int_equal(openchecks_items_item_size(result_items), item_size);

  OpenChecksItemsIterator items_iter =
      openchecks_items_iterator_new(result_items);
  size_t index = 0;
  OpenChecksItem const *item;

  for (; !openchecks_item_iterator_is_done(&items_iter);
       openchecks_item_iterator_next(&items_iter)) {
    item = openchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)openchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(openchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(openchecks_check_result_can_skip(&result), can_skip);

  // Cleanup
  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_failed(void **state) {
  (void)state;
  char *message = "test";
  size_t item_count = 5;
  size_t item_size = sizeof(IntItem);
  IntItems *items = create_int_items(item_count);

  for (size_t i = 0; i < item_count; i++) {
    IntItem item = create_int_item((int)i, NULL);
    int_items_set(items, i, item);
  }

  bool can_fix = false;
  bool can_skip = false;

  OpenChecksCheckResult result = openchecks_check_result_failed(
      message, (OpenChecksItems *)items, can_fix, can_skip);

  // Status
  assert_int_equal(openchecks_check_result_status(&result),
                   OpenChecksStatusFailed);
  // Message
  OpenChecksStringView result_message =
      openchecks_check_result_message(&result);
  assert_string_equal(result_message.string, message);
  // Items
  OpenChecksItems const *result_items = openchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(openchecks_items_length(result_items), item_count);
  assert_int_equal(openchecks_items_item_size(result_items), item_size);

  OpenChecksItemsIterator items_iter =
      openchecks_items_iterator_new(result_items);
  size_t index = 0;
  OpenChecksItem const *item;

  for (; !openchecks_item_iterator_is_done(&items_iter);
       openchecks_item_iterator_next(&items_iter)) {
    item = openchecks_item_iterator_item(&items_iter);
    assert_int_equal(*(int *)openchecks_item_value(item), index);
    index++;
  }

  // Can fix
  assert_int_equal(openchecks_check_result_can_fix(&result), can_fix);

  // Can skip
  assert_int_equal(openchecks_check_result_can_skip(&result), can_skip);

  // Cleanup
  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_destroy(void **state) {
  (void)state;
  OpenChecksStatus status;
  char *message;
  size_t item_count;
  IntItems *items;
  bool can_fix;
  bool can_skip;
  char *error;
  OpenChecksCheckResult result;

  // All pointers null.
  status = OpenChecksStatusPassed;
  message = NULL;
  item_count = 0;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
  openchecks_check_result_destroy(&result);

  // No pointers null.
  status = OpenChecksStatusPassed;
  message = "test";
  item_count = 5;
  items = create_int_items(item_count);
  can_fix = false;
  can_skip = false;
  error = "test";

  for (size_t i = 0; i < item_count; i++) {
    int_items_set(items, i, create_int_item((int)i, NULL));
  }

  result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_status(void **state) {
  (void)state;
  OpenChecksStatus status;
  char *message;
  IntItems *items;
  bool can_fix;
  bool can_skip;
  char *error;
  OpenChecksCheckResult result;

  OpenChecksStatus statuses[] = {
      OpenChecksStatusPending, OpenChecksStatusSkipped,
      OpenChecksStatusPassed,  OpenChecksStatusWarning,
      OpenChecksStatusFailed,  OpenChecksStatusSystemError,
  };

  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    items = NULL;
    can_fix = false;
    can_skip = false;
    error = NULL;
    result = openchecks_check_result_new(
        status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
    assert_int_equal(openchecks_check_result_status(&result), status);
    openchecks_check_result_destroy(&result);
  }
}

static void test_openchecks_check_result_message(void **state) {
  (void)state;
  OpenChecksStatus status;
  char *message;
  IntItems *items;
  bool can_fix;
  bool can_skip;
  char *error;
  OpenChecksCheckResult result;
  OpenChecksStringView msg;

  // Null message.
  status = OpenChecksStatusPassed;
  message = NULL;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
  msg = openchecks_check_result_message(&result);
  assert_string_equal(msg.string, "");
  openchecks_check_result_destroy(&result);

  // Non-null message.
  status = OpenChecksStatusPassed;
  message = "test";
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
  msg = openchecks_check_result_message(&result);
  assert_string_equal(msg.string, "test");
  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_items(void **state) {
  (void)state;
  OpenChecksStatus status;
  char *message;
  size_t item_count;
  size_t item_size;
  IntItems *items;
  bool can_fix;
  bool can_skip;
  char *error;
  OpenChecksCheckResult result;
  OpenChecksItems const *result_items;
  OpenChecksItemsIterator items_iter;
  OpenChecksItem const *item;

  // Null items.
  status = OpenChecksStatusPassed;
  message = NULL;
  item_count = 0;
  item_size = 0;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
  result_items = openchecks_check_result_items(&result);
  assert_null(result_items);

  items_iter = openchecks_items_iterator_new(result_items);
  assert_int_equal(items_iter.index, 0);
  assert_ptr_equal(items_iter.items, result_items);
  assert_null(items_iter.items);

  openchecks_check_result_destroy(&result);

  // 0 items.
  status = OpenChecksStatusPassed;
  message = NULL;
  item_count = 0;
  item_size = sizeof(IntItem);
  items = create_int_items(item_count);
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
  result_items = openchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(openchecks_items_item_size(result_items), item_size);
  assert_int_equal(openchecks_items_length(result_items), item_count);

  items_iter = openchecks_items_iterator_new(result_items);
  assert_int_equal(items_iter.index, 0);
  assert_ptr_equal(items_iter.items, result_items);
  assert_non_null(items_iter.items);

  assert_true(openchecks_item_iterator_is_done(&items_iter));
  assert_null(openchecks_item_iterator_item(&items_iter));
  assert_null(openchecks_item_iterator_next(&items_iter));

  openchecks_check_result_destroy(&result);

  // 1 item.
  status = OpenChecksStatusPassed;
  message = NULL;
  item_count = 1;
  item_size = sizeof(IntItem);
  items = create_int_items(1);
  can_fix = false;
  can_skip = false;
  error = NULL;

  int_items_set(items, 0, create_int_item(1, NULL));

  result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
  result_items = openchecks_check_result_items(&result);
  assert_non_null(result_items);
  assert_int_equal(openchecks_items_item_size(result_items), item_size);
  assert_int_equal(openchecks_items_length(result_items), item_count);

  items_iter = openchecks_items_iterator_new(result_items);
  assert_int_equal(items_iter.index, 0);
  assert_ptr_equal(items_iter.items, result_items);
  assert_non_null(items_iter.items);

  assert_false(openchecks_item_iterator_is_done(&items_iter));
  item = openchecks_item_iterator_item(&items_iter);
  assert_non_null(item);
  assert_int_equal(*(int *)openchecks_item_value(item), 1);
  item = openchecks_item_iterator_next(&items_iter);
  assert_true(openchecks_item_iterator_is_done(&items_iter));
  assert_int_equal(items_iter.index, 1);
  assert_non_null(item);
  assert_int_equal(*(int *)openchecks_item_value(item), 1);
  item = openchecks_item_iterator_item(&items_iter);
  assert_null(item);

  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_can_fix(void **state) {
  (void)state;
  OpenChecksStatus status;
  char *message;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  OpenChecksCheckResult result;

  OpenChecksStatus statuses[] = {
      OpenChecksStatusPending, OpenChecksStatusSkipped,
      OpenChecksStatusPassed,  OpenChecksStatusWarning,
      OpenChecksStatusFailed,  OpenChecksStatusSystemError,
  };

  // can_fix = true.
  bool expected[] = {true, true, true, true, true, false};

  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    items = NULL;
    can_fix = true;
    can_skip = false;
    error = NULL;

    result = openchecks_check_result_new(
        status, message, (OpenChecksItems *)items, can_fix, can_skip, error);

    assert_int_equal(openchecks_check_result_can_fix(&result), expected[i]);
    openchecks_check_result_destroy(&result);
  }

  // can_fix = false.
  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    items = NULL;
    can_fix = false;
    can_skip = false;
    error = NULL;

    result = openchecks_check_result_new(
        status, message, (OpenChecksItems *)items, can_fix, can_skip, error);

    assert_int_equal(openchecks_check_result_can_fix(&result), false);
    openchecks_check_result_destroy(&result);
  }
}

static void test_openchecks_check_result_can_skip(void **state) {
  (void)state;
  OpenChecksStatus status;
  char *message;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  OpenChecksCheckResult result;

  OpenChecksStatus statuses[] = {
      OpenChecksStatusPending, OpenChecksStatusSkipped,
      OpenChecksStatusPassed,  OpenChecksStatusWarning,
      OpenChecksStatusFailed,  OpenChecksStatusSystemError,
  };

  // can_fix = true.
  bool expected[] = {true, true, true, true, true, false};

  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    items = NULL;
    can_fix = false;
    can_skip = true;
    error = NULL;

    result = openchecks_check_result_new(
        status, message, (OpenChecksItems *)items, can_fix, can_skip, error);

    assert_int_equal(openchecks_check_result_can_skip(&result), expected[i]);
    openchecks_check_result_destroy(&result);
  }

  // can_fix = false.
  for (size_t i = 0; i < 6; i++) {
    status = statuses[i];
    message = NULL;
    items = NULL;
    can_fix = false;
    can_skip = false;
    error = NULL;

    result = openchecks_check_result_new(
        status, message, (OpenChecksItems *)items, can_fix, can_skip, error);

    assert_int_equal(openchecks_check_result_can_skip(&result), false);
    openchecks_check_result_destroy(&result);
  }
}

static void test_openchecks_check_result_error(void **state) {
  (void)state;
  OpenChecksStatus status;
  char *message;
  IntItem *items;
  bool can_fix;
  bool can_skip;
  char *error;
  OpenChecksCheckResult result;
  const char *msg;

  // Null error.
  status = OpenChecksStatusPassed;
  message = NULL;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = NULL;

  result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
  msg = openchecks_check_result_error(&result);
  assert_null(msg);
  openchecks_check_result_destroy(&result);

  // Non-null message.
  status = OpenChecksStatusPassed;
  message = NULL;
  items = NULL;
  can_fix = false;
  can_skip = false;
  error = "error";

  result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);
  msg = openchecks_check_result_error(&result);
  assert_string_equal(msg, "error");
  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_check_duration(void **state) {
  (void)state;
  OpenChecksStatus status = OpenChecksStatusPassed;
  char *message = NULL;
  IntItem *items = NULL;

  bool can_fix = false;
  bool can_skip = false;
  char *error = NULL;

  OpenChecksCheckResult result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);

  assert_double_equal(openchecks_check_result_check_duration(&result), 0.0,
                      DBL_EPSILON);

  openchecks_check_result_destroy(&result);
}

static void test_openchecks_check_result_fix_duration(void **state) {
  (void)state;
  OpenChecksStatus status = OpenChecksStatusPassed;
  char *message = NULL;
  IntItem *items = NULL;

  bool can_fix = false;
  bool can_skip = false;
  char *error = NULL;

  OpenChecksCheckResult result = openchecks_check_result_new(
      status, message, (OpenChecksItems *)items, can_fix, can_skip, error);

  assert_double_equal(openchecks_check_result_fix_duration(&result), 0.0,
                      DBL_EPSILON);

  openchecks_check_result_destroy(&result);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_openchecks_check_result_new),
      cmocka_unit_test(test_openchecks_check_result_passed),
      cmocka_unit_test(test_openchecks_check_result_new),
      cmocka_unit_test(test_openchecks_check_result_passed),
      cmocka_unit_test(test_openchecks_check_result_skipped),
      cmocka_unit_test(test_openchecks_check_result_warning),
      cmocka_unit_test(test_openchecks_check_result_failed),
      cmocka_unit_test(test_openchecks_check_result_destroy),
      cmocka_unit_test(test_openchecks_check_result_status),
      cmocka_unit_test(test_openchecks_check_result_message),
      cmocka_unit_test(test_openchecks_check_result_items),
      cmocka_unit_test(test_openchecks_check_result_can_fix),
      cmocka_unit_test(test_openchecks_check_result_can_skip),
      cmocka_unit_test(test_openchecks_check_result_error),
      cmocka_unit_test(test_openchecks_check_result_check_duration),
      cmocka_unit_test(test_openchecks_check_result_fix_duration),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
