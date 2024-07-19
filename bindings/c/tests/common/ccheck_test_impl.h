#ifndef openchecks_tests_ccheck
#define openchecks_tests_ccheck

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
  Test check
*/
typedef struct TestCheck {
  OpenChecksBaseCheck header;
} TestCheck;

const char *test_check_title_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "title";
}

const char *test_check_description_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

OpenChecksCheckHint test_check_hint_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return OPENCHECKS_CHECK_HINT_NONE | OPENCHECKS_CHECK_HINT_AUTO_FIX;
}

OpenChecksCheckResult test_check_run_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return openchecks_check_result_passed("test", NULL, false, false);
}

OpenChecksAutoFixResult test_check_auto_fix_fn(OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return openchecks_check_auto_fix_ok();
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
  OpenChecksBaseCheck header;
} AlwaysPassCheck;

const char *always_pass_check_title_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "Always Pass Check";
}

const char *always_pass_check_description_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

OpenChecksCheckHint
always_pass_check_hint_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return OPENCHECKS_CHECK_HINT_NONE | OPENCHECKS_CHECK_HINT_AUTO_FIX;
}

OpenChecksCheckResult
always_pass_check_run_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return openchecks_check_result_passed("test", NULL, false, false);
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
  OpenChecksBaseCheck header;
} AlwaysFailCheck;

const char *always_fail_check_title_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "Always Fail Check";
}

const char *always_fail_check_description_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

OpenChecksCheckHint
always_fail_check_hint_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return OPENCHECKS_CHECK_HINT_NONE | OPENCHECKS_CHECK_HINT_AUTO_FIX;
}

OpenChecksCheckResult
always_fail_check_run_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return openchecks_check_result_failed("test", NULL, false, false);
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
  OpenChecksBaseCheck header;
  uint8_t value;
} PassOnFixCheck;

const char *pass_on_fix_title_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "Pass On Fix Check";
}

const char *pass_on_fix_description_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

OpenChecksCheckHint pass_on_fix_hint_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return OPENCHECKS_CHECK_HINT_NONE | OPENCHECKS_CHECK_HINT_AUTO_FIX;
}

OpenChecksCheckResult pass_on_fix_run_fn(const OpenChecksBaseCheck *check) {
  if (((PassOnFixCheck *)check)->value != 0) {
    return openchecks_check_result_failed("failed", NULL, true, false);
  } else {
    return openchecks_check_result_passed("passed", NULL, false, false);
  }
}

OpenChecksAutoFixResult pass_on_fix_auto_fix_fn(OpenChecksBaseCheck *check) {
  ((PassOnFixCheck *)check)->value = 0;
  return openchecks_check_auto_fix_ok();
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
  OpenChecksBaseCheck header;
  uint8_t value;
} FailOnFixCheck;

const char *fail_on_fix_title_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "Fail On Fix Check";
}

const char *fail_on_fix_description_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

OpenChecksCheckHint fail_on_fix_hint_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return OPENCHECKS_CHECK_HINT_NONE | OPENCHECKS_CHECK_HINT_AUTO_FIX;
}

OpenChecksCheckResult fail_on_fix_run_fn(const OpenChecksBaseCheck *check) {
  if (((FailOnFixCheck *)check)->value != 0) {
    return openchecks_check_result_failed("failed", NULL, true, false);
  } else {
    return openchecks_check_result_passed("passed", NULL, false, false);
  }
}

OpenChecksAutoFixResult fail_on_fix_auto_fix_fn(OpenChecksBaseCheck *check) {
  ((FailOnFixCheck *)check)->value = 2;
  return openchecks_check_auto_fix_ok();
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
  OpenChecksBaseCheck header;
} NoAutoFixFlagCheck;

const char *no_auto_fix_flag_check_title_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "No Auto Fix Flag Check";
}

const char *
no_auto_fix_flag_check_description_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return "description";
}

OpenChecksCheckHint
no_auto_fix_flag_check_hint_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return OPENCHECKS_CHECK_HINT_NONE;
}

OpenChecksCheckResult
no_auto_fix_flag_check_run_fn(const OpenChecksBaseCheck *check) {
  (void)check; // Ignoring because the return value is static.
  return openchecks_check_result_failed("test", NULL, false, false);
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

#endif // openchecks_tests_ccheck
