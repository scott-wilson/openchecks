#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|status: checks::Status| {
    if status == checks::Status::Failed || status == checks::Status::SystemError {
        assert!(status.has_failed());
    } else {
        assert!(!status.has_failed());
    }
});
