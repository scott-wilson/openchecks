#include <float.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "ccheck_test_impl.h"
#include "citem_test_impl.h"
#include "citems_test_impl.h"
#include "openchecks.h"

/* ----------------------------------------------------------------------------
  Checks
*/
static void test_openchecks_check(void **state) {
  (void)state;
  TestCheck check = create_test_check();

  assert_string_equal(
      openchecks_check_title((OpenChecksBaseCheck *)&check).string, "title");
  assert_string_equal(
      openchecks_check_description((OpenChecksBaseCheck *)&check).string,
      "description");
  assert_int_equal(openchecks_check_hint((OpenChecksBaseCheck *)&check),
                   OPENCHECKS_CHECK_HINT_NONE | OPENCHECKS_CHECK_HINT_AUTO_FIX);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_openchecks_check),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
