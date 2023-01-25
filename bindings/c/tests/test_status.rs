use cchecks::*;

#[test]
fn test_status_is_pending_success() {
    unsafe {
        let status = CChecksStatus::CChecksStatusPending;
        assert!(cchecks_status_is_pending(&status));
        let status = CChecksStatus::CChecksStatusPending;
        assert!(cchecks_status_is_pending(&status));
        let status = CChecksStatus::CChecksStatusSkipped;
        assert!(!cchecks_status_is_pending(&status));
        let status = CChecksStatus::CChecksStatusPassed;
        assert!(!cchecks_status_is_pending(&status));
        let status = CChecksStatus::CChecksStatusWarning;
        assert!(!cchecks_status_is_pending(&status));
        let status = CChecksStatus::CChecksStatusFailed;
        assert!(!cchecks_status_is_pending(&status));
        let status = CChecksStatus::CChecksStatusSystemError;
        assert!(!cchecks_status_is_pending(&status));
    }
}

#[test]
fn test_status_has_passed_success() {
    unsafe {
        let status = CChecksStatus::CChecksStatusPending;
        assert!(!cchecks_status_has_passed(&status));
        let status = CChecksStatus::CChecksStatusSkipped;
        assert!(cchecks_status_has_passed(&status));
        let status = CChecksStatus::CChecksStatusPassed;
        assert!(cchecks_status_has_passed(&status));
        let status = CChecksStatus::CChecksStatusWarning;
        assert!(cchecks_status_has_passed(&status));
        let status = CChecksStatus::CChecksStatusFailed;
        assert!(!cchecks_status_has_passed(&status));
        let status = CChecksStatus::CChecksStatusSystemError;
        assert!(!cchecks_status_has_passed(&status));
    }
}

#[test]
fn test_status_has_failed_success() {
    unsafe {
        let status = CChecksStatus::CChecksStatusPending;
        assert!(!cchecks_status_has_failed(&status));
        let status = CChecksStatus::CChecksStatusSkipped;
        assert!(!cchecks_status_has_failed(&status));
        let status = CChecksStatus::CChecksStatusPassed;
        assert!(!cchecks_status_has_failed(&status));
        let status = CChecksStatus::CChecksStatusWarning;
        assert!(!cchecks_status_has_failed(&status));
        let status = CChecksStatus::CChecksStatusFailed;
        assert!(cchecks_status_has_failed(&status));
        let status = CChecksStatus::CChecksStatusSystemError;
        assert!(cchecks_status_has_failed(&status));
    }
}
