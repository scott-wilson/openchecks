mod c_string;
mod check;
mod item;
mod items;
mod result;
mod runner;
mod status;

pub use c_string::{cchecks_string_destroy, CChecksString, CChecksStringView};
pub use check::{
    cchecks_check_auto_fix_error, cchecks_check_auto_fix_ok, cchecks_check_description,
    cchecks_check_hint, cchecks_check_title, CChecksAutoFixResult, CChecksAutoFixStatus,
    CChecksBaseCheck, CCHECKS_CHECK_HINT_AUTO_FIX, CCHECKS_CHECK_HINT_NONE,
};
pub use item::{
    cchecks_item_debug, cchecks_item_display, cchecks_item_eq, cchecks_item_lt,
    cchecks_item_type_hint, cchecks_item_value, CChecksItem,
};
pub use items::{cchecks_items_new, CChecksItems, CChecksItemsIterator};
pub use result::{
    cchecks_check_result_can_fix, cchecks_check_result_can_skip,
    cchecks_check_result_check_duration, cchecks_check_result_destroy, cchecks_check_result_error,
    cchecks_check_result_failed, cchecks_check_result_fix_duration, cchecks_check_result_items,
    cchecks_check_result_message, cchecks_check_result_new, cchecks_check_result_passed,
    cchecks_check_result_skipped, cchecks_check_result_status, cchecks_check_result_warning,
    CChecksCheckResult,
};
pub use runner::{cchecks_auto_fix, cchecks_run};
pub use status::{
    cchecks_status_has_failed, cchecks_status_has_passed, cchecks_status_is_pending, CChecksStatus,
};
