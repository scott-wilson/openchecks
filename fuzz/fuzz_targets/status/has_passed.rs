#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|status: checks::Status| {
    if status == checks::Status::Passed || status == checks::Status::Warning {
        assert!(status.has_passed());
    } else {
        assert!(!status.has_passed());
    }
});
