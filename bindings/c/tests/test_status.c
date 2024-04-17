#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

#include "cchecks.h"

static void test_status_is_pending_success(void **state) {
  (void)state;
  CChecksStatus status;

  status = CChecksStatusPending;
  assert_true(cchecks_status_is_pending(&status));
  status = CChecksStatusSkipped;
  assert_false(cchecks_status_is_pending(&status));
  status = CChecksStatusPassed;
  assert_false(cchecks_status_is_pending(&status));
  status = CChecksStatusWarning;
  assert_false(cchecks_status_is_pending(&status));
  status = CChecksStatusFailed;
  assert_false(cchecks_status_is_pending(&status));
  status = CChecksStatusSystemError;
  assert_false(cchecks_status_is_pending(&status));
}

static void test_status_has_passed_success(void **state) {
  (void)state;
  CChecksStatus status;

  status = CChecksStatusPending;
  assert_false(cchecks_status_has_passed(&status));
  status = CChecksStatusSkipped;
  assert_false(cchecks_status_has_passed(&status));
  status = CChecksStatusPassed;
  assert_true(cchecks_status_has_passed(&status));
  status = CChecksStatusWarning;
  assert_true(cchecks_status_has_passed(&status));
  status = CChecksStatusFailed;
  assert_false(cchecks_status_has_passed(&status));
  status = CChecksStatusSystemError;
  assert_false(cchecks_status_has_passed(&status));
}

static void test_status_has_failed_success(void **state) {
  (void)state;
  CChecksStatus status;

  status = CChecksStatusPending;
  assert_false(cchecks_status_has_failed(&status));
  status = CChecksStatusSkipped;
  assert_false(cchecks_status_has_failed(&status));
  status = CChecksStatusPassed;
  assert_false(cchecks_status_has_failed(&status));
  status = CChecksStatusWarning;
  assert_false(cchecks_status_has_failed(&status));
  status = CChecksStatusFailed;
  assert_true(cchecks_status_has_failed(&status));
  status = CChecksStatusSystemError;
  assert_true(cchecks_status_has_failed(&status));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_status_is_pending_success),
      cmocka_unit_test(test_status_has_passed_success),
      cmocka_unit_test(test_status_has_failed_success),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
