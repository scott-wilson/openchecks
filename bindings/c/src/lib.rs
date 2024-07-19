mod c_string;
mod check;
mod item;
mod items;
mod result;
mod runner;
mod status;

pub use c_string::{openchecks_string_destroy, OpenChecksString, OpenChecksStringView};
pub use check::{
    openchecks_check_auto_fix_error, openchecks_check_auto_fix_ok, openchecks_check_description,
    openchecks_check_hint, openchecks_check_title, OpenChecksAutoFixResult,
    OpenChecksAutoFixStatus, OpenChecksBaseCheck, OpenChecksCheckHint,
    OPENCHECKS_CHECK_HINT_AUTO_FIX, OPENCHECKS_CHECK_HINT_NONE,
};
pub use item::{
    openchecks_item_clone, openchecks_item_debug, openchecks_item_destroy, openchecks_item_display,
    openchecks_item_eq, openchecks_item_lt, openchecks_item_type_hint, openchecks_item_value,
    OpenChecksItem,
};
pub use items::{
    openchecks_item_iterator_is_done, openchecks_item_iterator_item, openchecks_item_iterator_next,
    openchecks_items_clone, openchecks_items_destroy, openchecks_items_eq, openchecks_items_get,
    openchecks_items_item_size, openchecks_items_iterator_new, openchecks_items_length,
    OpenChecksItems, OpenChecksItemsIterator,
};
pub use result::{
    openchecks_check_result_can_fix, openchecks_check_result_can_skip,
    openchecks_check_result_check_duration, openchecks_check_result_destroy,
    openchecks_check_result_error, openchecks_check_result_failed,
    openchecks_check_result_fix_duration, openchecks_check_result_items,
    openchecks_check_result_message, openchecks_check_result_new, openchecks_check_result_passed,
    openchecks_check_result_skipped, openchecks_check_result_status,
    openchecks_check_result_warning, OpenChecksCheckResult,
};
pub use runner::{openchecks_auto_fix, openchecks_run};
pub use status::{
    openchecks_status_has_failed, openchecks_status_has_passed, openchecks_status_is_pending,
    OpenChecksStatus,
};
