/// The status enum represents a result status.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CChecksStatus {
    /// The check is waiting to run. A check should not return this status, but
    /// instead this can be used by a user interface to let a user know that the
    /// check is ready to run.
    CChecksStatusPending,
    /// The check has been skipped. A check might return this to let the user
    /// know that an element it depends on is invalid (such as a file doesn't)
    /// exist, or a check scheduler may make child checks return this status if
    /// a check fails.
    CChecksStatusSkipped,
    /// The check has successfully passed without issue.
    CChecksStatusPassed,
    /// There were issues found, but they are not deemed failures. This can be
    /// treated the same as a pass.
    CChecksStatusWarning,
    /// The check found an issue that caused it to fail. A validation system
    /// should block the process following the validations to have the issue
    /// fixed, unless the result allows skipping the check.
    CChecksStatusFailed,
    /// There was an issue with a check or runner itself. For example, code that
    /// the check depends on has an error, or the check is otherwise invalid.
    /// If a validation process finds a result with this status, then the
    /// process should not let the next process after run at all until the check
    /// has been fixed by a developer.
    CChecksStatusSystemError,
}

impl std::convert::From<checks::Status> for CChecksStatus {
    fn from(status: checks::Status) -> Self {
        match status {
            checks::Status::Pending => Self::CChecksStatusPending,
            checks::Status::Skipped => Self::CChecksStatusSkipped,
            checks::Status::Passed => Self::CChecksStatusPassed,
            checks::Status::Warning => Self::CChecksStatusWarning,
            checks::Status::Failed => Self::CChecksStatusFailed,
            checks::Status::SystemError => Self::CChecksStatusSystemError,
        }
    }
}

impl std::convert::From<CChecksStatus> for checks::Status {
    fn from(status: CChecksStatus) -> Self {
        match status {
            CChecksStatus::CChecksStatusPending => Self::Pending,
            CChecksStatus::CChecksStatusSkipped => Self::Skipped,
            CChecksStatus::CChecksStatusPassed => Self::Passed,
            CChecksStatus::CChecksStatusWarning => Self::Warning,
            CChecksStatus::CChecksStatusFailed => Self::Failed,
            CChecksStatus::CChecksStatusSystemError => Self::SystemError,
        }
    }
}

/// Return if a check is waiting to be run.
///
/// # Safety
///
/// The status must not be a null pointer.
#[no_mangle]
pub unsafe extern "C" fn cchecks_status_is_pending(status: *const CChecksStatus) -> bool {
    let status = match unsafe { status.as_ref() } {
        Some(s) => s,
        None => panic!("cchecks_status_is_pending received a null pointer."),
    };
    let status: checks::Status = (*status).into();
    status.is_pending()
}

/// Return if a check has passed.
///
/// # Safety
///
/// The status must not be a null pointer.
#[no_mangle]
pub unsafe extern "C" fn cchecks_status_has_passed(status: *const CChecksStatus) -> bool {
    let status = match unsafe { status.as_ref() } {
        Some(s) => s,
        None => panic!("cchecks_status_has_passed received a null pointer."),
    };
    let status: checks::Status = (*status).into();
    status.has_passed()
}

/// Return if a check has failed.
///
/// # Safety
///
/// The status must not be a null pointer.
#[no_mangle]
pub unsafe extern "C" fn cchecks_status_has_failed(status: *const CChecksStatus) -> bool {
    let status = match unsafe { status.as_ref() } {
        Some(s) => s,
        None => panic!("cchecks_status_has_failed received a null pointer."),
    };
    let status: checks::Status = (*status).into();
    status.has_failed()
}
