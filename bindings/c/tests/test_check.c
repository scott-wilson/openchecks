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
#include "citems_test_impl.h"

/* ----------------------------------------------------------------------------
  Checks
*/
static void test_cchecks_check(void **state) {
  TestCheck check = create_test_check();

  assert_string_equal(cchecks_check_title((CChecksBaseCheck *)&check).string,
                      "title");
  assert_string_equal(
      cchecks_check_description((CChecksBaseCheck *)&check).string,
      "description");
  assert_int_equal(cchecks_check_hint((CChecksBaseCheck *)&check),
                   CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_cchecks_check),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
