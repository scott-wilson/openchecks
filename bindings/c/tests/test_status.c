#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

#include "openchecks.h"

static void test_status_is_pending_success(void **state) {
  (void)state;
  OpenChecksStatus status;

  status = OpenChecksStatusPending;
  assert_true(openchecks_status_is_pending(&status));
  status = OpenChecksStatusSkipped;
  assert_false(openchecks_status_is_pending(&status));
  status = OpenChecksStatusPassed;
  assert_false(openchecks_status_is_pending(&status));
  status = OpenChecksStatusWarning;
  assert_false(openchecks_status_is_pending(&status));
  status = OpenChecksStatusFailed;
  assert_false(openchecks_status_is_pending(&status));
  status = OpenChecksStatusSystemError;
  assert_false(openchecks_status_is_pending(&status));
}

static void test_status_has_passed_success(void **state) {
  (void)state;
  OpenChecksStatus status;

  status = OpenChecksStatusPending;
  assert_false(openchecks_status_has_passed(&status));
  status = OpenChecksStatusSkipped;
  assert_false(openchecks_status_has_passed(&status));
  status = OpenChecksStatusPassed;
  assert_true(openchecks_status_has_passed(&status));
  status = OpenChecksStatusWarning;
  assert_true(openchecks_status_has_passed(&status));
  status = OpenChecksStatusFailed;
  assert_false(openchecks_status_has_passed(&status));
  status = OpenChecksStatusSystemError;
  assert_false(openchecks_status_has_passed(&status));
}

static void test_status_has_failed_success(void **state) {
  (void)state;
  OpenChecksStatus status;

  status = OpenChecksStatusPending;
  assert_false(openchecks_status_has_failed(&status));
  status = OpenChecksStatusSkipped;
  assert_false(openchecks_status_has_failed(&status));
  status = OpenChecksStatusPassed;
  assert_false(openchecks_status_has_failed(&status));
  status = OpenChecksStatusWarning;
  assert_false(openchecks_status_has_failed(&status));
  status = OpenChecksStatusFailed;
  assert_true(openchecks_status_has_failed(&status));
  status = OpenChecksStatusSystemError;
  assert_true(openchecks_status_has_failed(&status));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_status_is_pending_success),
      cmocka_unit_test(test_status_has_passed_success),
      cmocka_unit_test(test_status_has_failed_success),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
