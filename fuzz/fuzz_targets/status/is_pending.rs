#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|status: openchecks::Status| {
    if status == openchecks::Status::Pending {
        assert!(status.is_pending());
    } else {
        assert!(!status.is_pending());
    }
});
