#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|status: openchecks::Status| {
    if status == openchecks::Status::Passed || status == openchecks::Status::Warning {
        assert!(status.has_passed());
    } else {
        assert!(!status.has_passed());
    }
});
