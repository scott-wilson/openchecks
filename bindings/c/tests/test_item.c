#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "citem_test_impl.h"
#include "openchecks.h"

/* ----------------------------------------------------------------------------
  Checks
*/
static void test_item_type_hint_success(void **state) {
  (void)state;
  const char *result;
  IntItem item;

  // Test with a hint with text.
  item = create_int_item(1, "test");
  result = openchecks_item_type_hint((OpenChecksItem *)&item);

  assert_string_equal(result, "test");
  openchecks_item_destroy((OpenChecksItem *)&item);

  // Test with a null hint.
  item = create_int_item(1, NULL);

  result = openchecks_item_type_hint((OpenChecksItem *)&item);

  assert_null(result);
  openchecks_item_destroy((OpenChecksItem *)&item);
}

static void test_item_value_success(void **state) {
  (void)state;
  IntItem int_item;
  const void *result;

  int_item = create_int_item(1, "test");
  result = openchecks_item_value((OpenChecksItem *)&int_item);
  int *int_result = (int *)result;

  assert_int_equal(*int_result, 1);
  openchecks_item_destroy((OpenChecksItem *)&int_item);

  StringItem string_item;

  string_item = create_string_item("test", NULL);
  result = openchecks_item_value((OpenChecksItem *)&string_item);
  char *string_result = (char *)result;

  assert_string_equal(string_result, "test");
  destroy_string_item(&string_item);
}

static void test_item_clone_success(void **state) {
  (void)state;
  IntItem int_item;

  int_item = create_int_item(1, "test");
  IntItem *new_int_item =
      (IntItem *)openchecks_item_clone((OpenChecksItem *)&int_item);

  assert_int_equal(int_item.value, new_int_item->value);
  assert_string_equal(int_item.type_hint, new_int_item->type_hint);
  assert_ptr_not_equal(&int_item.value, new_int_item->value);
  assert_ptr_not_equal(&int_item.type_hint, new_int_item->type_hint);

  openchecks_item_destroy((OpenChecksItem *)&int_item);
  openchecks_item_destroy((OpenChecksItem *)new_int_item);

  StringItem string_item;

  string_item = create_string_item("test", "test");
  StringItem *new_string_item =
      (StringItem *)openchecks_item_clone((OpenChecksItem *)&string_item);

  assert_string_equal(string_item.value, new_string_item->value);
  assert_string_equal(string_item.type_hint, new_string_item->type_hint);
  assert_ptr_not_equal(&string_item.value, new_string_item->value);
  assert_ptr_not_equal(&string_item.type_hint, new_string_item->type_hint);

  destroy_string_item(&string_item);
  destroy_string_item(new_string_item);
}

static void test_item_debug_success(void **state) {
  (void)state;
  OpenChecksString debug_string;

  IntItem int_item;

  int_item = create_int_item(1, "test");
  debug_string = openchecks_item_debug((OpenChecksItem *)&int_item);

  assert_string_equal(debug_string.string, "Item(1)");
  openchecks_string_destroy(&debug_string);
  openchecks_item_destroy((OpenChecksItem *)&int_item);

  StringItem string_item;

  string_item = create_string_item("test", "test");
  debug_string = openchecks_item_debug((OpenChecksItem *)&string_item);

  assert_string_equal(debug_string.string, "Item(test)");
  openchecks_string_destroy(&debug_string);
  destroy_string_item(&string_item);
}

static void test_item_display_success(void **state) {
  (void)state;
  OpenChecksString display_string;

  IntItem int_item;

  int_item = create_int_item(1, "test");
  display_string = openchecks_item_display((OpenChecksItem *)&int_item);

  assert_string_equal(display_string.string, "1");
  openchecks_string_destroy(&display_string);
  openchecks_item_destroy((OpenChecksItem *)&int_item);

  StringItem string_item;

  string_item = create_string_item("test", "test");
  display_string = openchecks_item_display((OpenChecksItem *)&string_item);

  assert_string_equal(display_string.string, "test");
  openchecks_string_destroy(&display_string);
  destroy_string_item(&string_item);
}

static void test_item_lt_success(void **state) {
  (void)state;
  IntItem a_int_item, b_int_item;

  // Int: A < B
  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(2, NULL);

  assert_true(openchecks_item_lt((OpenChecksItem *)&a_int_item,
                                 (OpenChecksItem *)&b_int_item));

  openchecks_item_destroy((OpenChecksItem *)&a_int_item);
  openchecks_item_destroy((OpenChecksItem *)&b_int_item);

  // Int: A == B
  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(1, NULL);

  assert_false(openchecks_item_lt((OpenChecksItem *)&a_int_item,
                                  (OpenChecksItem *)&b_int_item));
  openchecks_item_destroy((OpenChecksItem *)&a_int_item);
  openchecks_item_destroy((OpenChecksItem *)&b_int_item);

  // Int: A > B
  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(0, NULL);

  assert_false(openchecks_item_lt((OpenChecksItem *)&a_int_item,
                                  (OpenChecksItem *)&b_int_item));
  openchecks_item_destroy((OpenChecksItem *)&a_int_item);
  openchecks_item_destroy((OpenChecksItem *)&b_int_item);

  StringItem a_string_item, b_string_item;

  // String: A < B
  a_string_item = create_string_item("a", NULL);
  b_string_item = create_string_item("b", NULL);

  assert_true(openchecks_item_lt((OpenChecksItem *)&a_string_item,
                                 (OpenChecksItem *)&b_string_item));

  destroy_string_item(&a_string_item);
  destroy_string_item(&b_string_item);

  // String: A == B
  a_string_item = create_string_item("a", NULL);
  b_string_item = create_string_item("a", NULL);

  assert_false(openchecks_item_lt((OpenChecksItem *)&a_string_item,
                                  (OpenChecksItem *)&b_string_item));
  destroy_string_item(&a_string_item);
  destroy_string_item(&b_string_item);

  // String: A > B
  a_string_item = create_string_item("b", NULL);
  b_string_item = create_string_item("a", NULL);

  assert_false(openchecks_item_lt((OpenChecksItem *)&a_string_item,
                                  (OpenChecksItem *)&b_string_item));
  destroy_string_item(&a_string_item);
  destroy_string_item(&b_string_item);
}

static void test_item_eq_success(void **state) {
  (void)state;
  IntItem a_int_item, b_int_item;

  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(1, NULL);

  assert_true(openchecks_item_eq((OpenChecksItem *)&a_int_item,
                                 (OpenChecksItem *)&b_int_item));

  openchecks_item_destroy((OpenChecksItem *)&a_int_item);
  openchecks_item_destroy((OpenChecksItem *)&b_int_item);

  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(2, NULL);

  assert_false(openchecks_item_eq((OpenChecksItem *)&a_int_item,
                                  (OpenChecksItem *)&b_int_item));
  openchecks_item_destroy((OpenChecksItem *)&a_int_item);
  openchecks_item_destroy((OpenChecksItem *)&b_int_item);

  StringItem a_string_item, b_string_item;

  a_string_item = create_string_item("1", NULL);
  b_string_item = create_string_item("1", NULL);

  assert_true(openchecks_item_eq((OpenChecksItem *)&a_string_item,
                                 (OpenChecksItem *)&b_string_item));

  destroy_string_item(&a_string_item);
  destroy_string_item(&b_string_item);

  a_string_item = create_string_item("1", NULL);
  b_string_item = create_string_item("2", NULL);

  assert_false(openchecks_item_eq((OpenChecksItem *)&a_string_item,
                                  (OpenChecksItem *)&b_string_item));
  destroy_string_item(&a_string_item);
  destroy_string_item(&b_string_item);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_item_type_hint_success),
      cmocka_unit_test(test_item_value_success),
      cmocka_unit_test(test_item_clone_success),
      cmocka_unit_test(test_item_debug_success),
      cmocka_unit_test(test_item_display_success),
      cmocka_unit_test(test_item_lt_success),
      cmocka_unit_test(test_item_eq_success),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
