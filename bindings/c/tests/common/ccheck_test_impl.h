#ifndef cchecks_tests_ccheck
#define cchecks_tests_ccheck

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
  Test check
*/
typedef struct TestCheck {
  CChecksBaseCheck header;
} TestCheck;

const char *test_check_title_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "title";
}

const char *test_check_description_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

CChecksCheckHint test_check_hint_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX;
}

CChecksCheckResult test_check_run_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return cchecks_check_result_passed("test", NULL, false, false);
}

CChecksAutoFixResult test_check_auto_fix_fn(CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return cchecks_check_auto_fix_ok();
}

TestCheck create_test_check() {
  TestCheck check;
  check.header.title_fn = test_check_title_fn;
  check.header.description_fn = test_check_description_fn;
  check.header.hint_fn = test_check_hint_fn;
  check.header.check_fn = test_check_run_fn;
  check.header.auto_fix_fn = test_check_auto_fix_fn;

  return check;
}

/* ----------------------------------------------------------------------------
  Always pass check
*/
typedef struct AlwaysPassCheck {
  CChecksBaseCheck header;
} AlwaysPassCheck;

const char *always_pass_check_title_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "Always Pass Check";
}

const char *always_pass_check_description_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

CChecksCheckHint always_pass_check_hint_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX;
}

CChecksCheckResult always_pass_check_run_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return cchecks_check_result_passed("test", NULL, false, false);
}

AlwaysPassCheck create_always_pass_check() {
  AlwaysPassCheck check;
  check.header.title_fn = always_pass_check_title_fn;
  check.header.description_fn = always_pass_check_description_fn;
  check.header.hint_fn = always_pass_check_hint_fn;
  check.header.check_fn = always_pass_check_run_fn;
  check.header.auto_fix_fn = NULL;

  return check;
}

/* ----------------------------------------------------------------------------
  Always fail check
*/
typedef struct AlwaysFailCheck {
  CChecksBaseCheck header;
} AlwaysFailCheck;

const char *always_fail_check_title_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "Always Fail Check";
}

const char *always_fail_check_description_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

CChecksCheckHint always_fail_check_hint_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX;
}

CChecksCheckResult always_fail_check_run_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return cchecks_check_result_failed("test", NULL, false, false);
}

AlwaysFailCheck create_always_fail_check() {
  AlwaysFailCheck check;
  check.header.title_fn = always_fail_check_title_fn;
  check.header.description_fn = always_fail_check_description_fn;
  check.header.hint_fn = always_fail_check_hint_fn;
  check.header.check_fn = always_fail_check_run_fn;
  check.header.auto_fix_fn = NULL;

  return check;
}
/* ----------------------------------------------------------------------------
  Pass on fix check
*/
typedef struct PassOnFixCheck {
  CChecksBaseCheck header;
  uint8_t value;
} PassOnFixCheck;

const char *pass_on_fix_title_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "Pass On Fix Check";
}

const char *pass_on_fix_description_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

CChecksCheckHint pass_on_fix_hint_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX;
}

CChecksCheckResult pass_on_fix_run_fn(const CChecksBaseCheck *check) {
  if (((PassOnFixCheck *)check)->value != 0) {
    return cchecks_check_result_failed("failed", NULL, true, false);
  } else {
    return cchecks_check_result_passed("passed", NULL, false, false);
  }
}

CChecksAutoFixResult pass_on_fix_auto_fix_fn(CChecksBaseCheck *check) {
  ((PassOnFixCheck *)check)->value = 0;
  return cchecks_check_auto_fix_ok();
}

PassOnFixCheck create_pass_on_fix() {
  PassOnFixCheck check;
  check.header.title_fn = pass_on_fix_title_fn;
  check.header.description_fn = pass_on_fix_description_fn;
  check.header.hint_fn = pass_on_fix_hint_fn;
  check.header.check_fn = pass_on_fix_run_fn;
  check.header.auto_fix_fn = pass_on_fix_auto_fix_fn;
  check.value = 1;

  return check;
}

/* ----------------------------------------------------------------------------
  Fail on fix check
*/
typedef struct FailOnFixCheck {
  CChecksBaseCheck header;
  uint8_t value;
} FailOnFixCheck;

const char *fail_on_fix_title_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "Fail On Fix Check";
}

const char *fail_on_fix_description_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

CChecksCheckHint fail_on_fix_hint_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX;
}

CChecksCheckResult fail_on_fix_run_fn(const CChecksBaseCheck *check) {
  if (((FailOnFixCheck *)check)->value != 0) {
    return cchecks_check_result_failed("failed", NULL, true, false);
  } else {
    return cchecks_check_result_passed("passed", NULL, false, false);
  }
}

CChecksAutoFixResult fail_on_fix_auto_fix_fn(CChecksBaseCheck *check) {
  ((FailOnFixCheck *)check)->value = 2;
  return cchecks_check_auto_fix_ok();
}

FailOnFixCheck create_fail_on_fix() {
  FailOnFixCheck check;
  check.header.title_fn = fail_on_fix_title_fn;
  check.header.description_fn = fail_on_fix_description_fn;
  check.header.hint_fn = fail_on_fix_hint_fn;
  check.header.check_fn = fail_on_fix_run_fn;
  check.header.auto_fix_fn = fail_on_fix_auto_fix_fn;
  check.value = 1;

  return check;
}

/* ----------------------------------------------------------------------------
  No auto-fix flag check
*/
typedef struct NoAutoFixFlagCheck {
  CChecksBaseCheck header;
} NoAutoFixFlagCheck;

const char *no_auto_fix_flag_check_title_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "No Auto Fix Flag Check";
}

const char *
no_auto_fix_flag_check_description_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

CChecksCheckHint no_auto_fix_flag_check_hint_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return CCHECKS_CHECK_HINT_NONE;
}

CChecksCheckResult
no_auto_fix_flag_check_run_fn(const CChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return cchecks_check_result_failed("test", NULL, false, false);
}

NoAutoFixFlagCheck create_no_auto_fix_flag_check() {
  NoAutoFixFlagCheck check;
  check.header.title_fn = no_auto_fix_flag_check_title_fn;
  check.header.description_fn = no_auto_fix_flag_check_description_fn;
  check.header.hint_fn = no_auto_fix_flag_check_hint_fn;
  check.header.check_fn = no_auto_fix_flag_check_run_fn;
  check.header.auto_fix_fn = NULL;

  return check;
}

#endif // cchecks_tests_ccheck
