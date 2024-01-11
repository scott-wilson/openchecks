use std::ffi::CStr;

use cchecks::*;
mod common;
use common::*;

/* ----------------------------------------------------------------------------
  Checks
*/
#[test]
fn test_cchecks_check() {
    unsafe {
        let check = create_test_check();
        let check = (&check) as *const TestCheck as *const CChecksBaseCheck;

        let title = CStr::from_ptr(cchecks_check_title(check).string).to_string_lossy();
        assert_eq!(title, "title");
        let title = CStr::from_ptr(cchecks_check_description(check).string).to_string_lossy();
        assert_eq!(title, "description");
        assert_eq!(
            cchecks_check_hint(check),
            CCHECKS_CHECK_HINT_NONE | CCHECKS_CHECK_HINT_AUTO_FIX
        );
    }
}
