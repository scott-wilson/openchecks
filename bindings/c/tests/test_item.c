#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "cchecks.h"
#include "citem_test_impl.h"

/* ----------------------------------------------------------------------------
  Checks
*/
static void test_item_type_hint_success(void **state) {
  (void)state;
  const char *result;
  IntItem item;

  // Test with a hint with text.
  item = create_int_item(1, "test");
  result = cchecks_item_type_hint((CChecksItem *)&item);

  assert_string_equal(result, "test");
  cchecks_item_destroy((CChecksItem *)&item);

  // Test with a null hint.
  item = create_int_item(1, NULL);

  result = cchecks_item_type_hint((CChecksItem *)&item);

  assert_null(result);
  cchecks_item_destroy((CChecksItem *)&item);
}

static void test_item_value_success(void **state) {
  (void)state;
  IntItem int_item;
  const void *result;

  int_item = create_int_item(1, "test");
  result = cchecks_item_value((CChecksItem *)&int_item);
  int *int_result = (int *)result;

  assert_int_equal(*int_result, 1);
  cchecks_item_destroy((CChecksItem *)&int_item);

  StringItem string_item;

  string_item = create_string_item("test", NULL);
  result = cchecks_item_value((CChecksItem *)&string_item);
  char *string_result = (char *)result;

  assert_string_equal(string_result, "test");
  destroy_string_item(&string_item);
}

static void test_item_clone_success(void **state) {
  (void)state;
  IntItem int_item;

  int_item = create_int_item(1, "test");
  IntItem *new_int_item =
      (IntItem *)cchecks_item_clone((CChecksItem *)&int_item);

  assert_int_equal(int_item.value, new_int_item->value);
  assert_string_equal(int_item.type_hint, new_int_item->type_hint);
  assert_ptr_not_equal(&int_item.value, new_int_item->value);
  assert_ptr_not_equal(&int_item.type_hint, new_int_item->type_hint);

  cchecks_item_destroy((CChecksItem *)&int_item);
  cchecks_item_destroy((CChecksItem *)&new_int_item);

  StringItem string_item;

  string_item = create_string_item("test", "test");
  StringItem *new_string_item =
      (StringItem *)cchecks_item_clone((CChecksItem *)&string_item);

  assert_string_equal(string_item.value, new_string_item->value);
  assert_string_equal(string_item.type_hint, new_string_item->type_hint);
  assert_ptr_not_equal(&string_item.value, new_string_item->value);
  assert_ptr_not_equal(&string_item.type_hint, new_string_item->type_hint);

  destroy_string_item(&string_item);
  destroy_string_item(new_string_item);
}

static void test_item_debug_success(void **state) {
  (void)state;
  CChecksString debug_string;

  IntItem int_item;

  int_item = create_int_item(1, "test");
  debug_string = cchecks_item_debug((CChecksItem *)&int_item);

  assert_string_equal(debug_string.string, "Item(1)");
  cchecks_string_destroy(&debug_string);
  cchecks_item_destroy((CChecksItem *)&int_item);

  StringItem string_item;

  string_item = create_string_item("test", "test");
  debug_string = cchecks_item_debug((CChecksItem *)&string_item);

  assert_string_equal(debug_string.string, "Item(test)");
  cchecks_string_destroy(&debug_string);
  destroy_string_item(&string_item);
}

static void test_item_display_success(void **state) {
  (void)state;
  CChecksString display_string;

  IntItem int_item;

  int_item = create_int_item(1, "test");
  display_string = cchecks_item_display((CChecksItem *)&int_item);

  assert_string_equal(display_string.string, "1");
  cchecks_string_destroy(&display_string);
  cchecks_item_destroy((CChecksItem *)&int_item);

  StringItem string_item;

  string_item = create_string_item("test", "test");
  display_string = cchecks_item_display((CChecksItem *)&string_item);

  assert_string_equal(display_string.string, "test");
  cchecks_string_destroy(&display_string);
  destroy_string_item(&string_item);
}

static void test_item_lt_success(void **state) {
  (void)state;
  IntItem a_int_item, b_int_item;

  // Int: A < B
  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(2, NULL);

  assert_true(
      cchecks_item_lt((CChecksItem *)&a_int_item, (CChecksItem *)&b_int_item));

  cchecks_item_destroy((CChecksItem *)&a_int_item);
  cchecks_item_destroy((CChecksItem *)&b_int_item);

  // Int: A == B
  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(1, NULL);

  assert_false(
      cchecks_item_lt((CChecksItem *)&a_int_item, (CChecksItem *)&b_int_item));
  cchecks_item_destroy((CChecksItem *)&a_int_item);
  cchecks_item_destroy((CChecksItem *)&b_int_item);

  // Int: A > B
  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(0, NULL);

  assert_false(
      cchecks_item_lt((CChecksItem *)&a_int_item, (CChecksItem *)&b_int_item));
  cchecks_item_destroy((CChecksItem *)&a_int_item);
  cchecks_item_destroy((CChecksItem *)&b_int_item);

  StringItem a_string_item, b_string_item;

  // String: A < B
  a_string_item = create_string_item("a", NULL);
  b_string_item = create_string_item("b", NULL);

  assert_true(cchecks_item_lt((CChecksItem *)&a_string_item,
                              (CChecksItem *)&b_string_item));

  destroy_string_item(&a_string_item);
  destroy_string_item(&b_string_item);

  // String: A == B
  a_string_item = create_string_item("a", NULL);
  b_string_item = create_string_item("a", NULL);

  assert_false(cchecks_item_lt((CChecksItem *)&a_string_item,
                               (CChecksItem *)&b_string_item));
  destroy_string_item(&a_string_item);
  destroy_string_item(&b_string_item);

  // String: A > B
  a_string_item = create_string_item("b", NULL);
  b_string_item = create_string_item("a", NULL);

  assert_false(cchecks_item_lt((CChecksItem *)&a_string_item,
                               (CChecksItem *)&b_string_item));
  destroy_string_item(&a_string_item);
  destroy_string_item(&b_string_item);
}

static void test_item_eq_success(void **state) {
  (void)state;
  IntItem a_int_item, b_int_item;

  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(1, NULL);

  assert_true(
      cchecks_item_eq((CChecksItem *)&a_int_item, (CChecksItem *)&b_int_item));

  cchecks_item_destroy((CChecksItem *)&a_int_item);
  cchecks_item_destroy((CChecksItem *)&b_int_item);

  a_int_item = create_int_item(1, NULL);
  b_int_item = create_int_item(2, NULL);

  assert_false(
      cchecks_item_eq((CChecksItem *)&a_int_item, (CChecksItem *)&b_int_item));
  cchecks_item_destroy((CChecksItem *)&a_int_item);
  cchecks_item_destroy((CChecksItem *)&b_int_item);

  StringItem a_string_item, b_string_item;

  a_string_item = create_string_item("1", NULL);
  b_string_item = create_string_item("1", NULL);

  assert_true(cchecks_item_eq((CChecksItem *)&a_string_item,
                              (CChecksItem *)&b_string_item));

  destroy_string_item(&a_string_item);
  destroy_string_item(&b_string_item);

  a_string_item = create_string_item("1", NULL);
  b_string_item = create_string_item("2", NULL);

  assert_false(cchecks_item_eq((CChecksItem *)&a_string_item,
                               (CChecksItem *)&b_string_item));
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
