#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|status: openchecks::Status| {
    if status == openchecks::Status::Failed || status == openchecks::Status::SystemError {
        assert!(status.has_failed());
    } else {
        assert!(!status.has_failed());
    }
});
