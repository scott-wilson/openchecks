#include <float.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "ccheck_test_impl.h"
#include "cchecks.h"
#include "citem_test_impl.h"

/* ----------------------------------------------------------------------------
  Checks
*/
static void test_always_pass_check(void **state) {
  AlwaysPassCheck check = create_always_pass_check();
  CChecksCheckResult result = cchecks_run((CChecksBaseCheck *)&check);
  assert_int_equal(cchecks_status_has_passed(&result.status), true);
  cchecks_check_result_destroy(&result);
}

static void test_always_fail_check(void **state) {
  AlwaysFailCheck check = create_always_fail_check();
  CChecksCheckResult result = cchecks_run((CChecksBaseCheck *)&check);
  assert_int_equal(cchecks_status_has_passed(&result.status), false);
  cchecks_check_result_destroy(&result);
}

static void test_pass_on_fix_check(void **state) {
  PassOnFixCheck check = create_pass_on_fix();
  CChecksCheckResult result;
  result = cchecks_run((CChecksBaseCheck *)&check);
  assert_int_equal(cchecks_status_has_passed(&result.status), false);
  cchecks_check_result_destroy(&result);

  result = cchecks_auto_fix((CChecksBaseCheck *)&check);
  assert_int_equal(cchecks_status_has_passed(&result.status), true);
  cchecks_check_result_destroy(&result);
}

static void test_fail_on_fix_check(void **state) {
  FailOnFixCheck check = create_fail_on_fix();
  CChecksCheckResult result;
  result = cchecks_run((CChecksBaseCheck *)&check);
  assert_int_equal(cchecks_status_has_passed(&result.status), false);
  cchecks_check_result_destroy(&result);

  result = cchecks_auto_fix((CChecksBaseCheck *)&check);
  assert_int_equal(cchecks_status_has_passed(&result.status), false);
  cchecks_check_result_destroy(&result);
}

static void test_no_auto_fix_flag_check(void **state) {
  NoAutoFixFlagCheck check = create_no_auto_fix_flag_check();
  CChecksCheckResult result = cchecks_auto_fix((CChecksBaseCheck *)&check);
  assert_int_equal(result.status, CChecksStatusSystemError);
  cchecks_check_result_destroy(&result);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_always_pass_check),
      cmocka_unit_test(test_always_fail_check),
      cmocka_unit_test(test_pass_on_fix_check),
      cmocka_unit_test(test_fail_on_fix_check),
      cmocka_unit_test(test_no_auto_fix_flag_check),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
