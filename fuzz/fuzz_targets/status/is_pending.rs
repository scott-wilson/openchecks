#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|status: checks::Status| {
    if status == checks::Status::Pending {
        assert!(status.is_pending());
    } else {
        assert!(!status.is_pending());
    }
});
