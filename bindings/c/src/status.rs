/// The status enum represents a result status.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum OpenChecksStatus {
    /// The check is waiting to run. A check should not return this status, but
    /// instead this can be used by a user interface to let a user know that the
    /// check is ready to run.
    OpenChecksStatusPending,
    /// The check has been skipped. A check might return this to let the user
    /// know that an element it depends on is invalid (such as a file doesn't)
    /// exist, or a check scheduler may make child checks return this status if
    /// a check fails.
    OpenChecksStatusSkipped,
    /// The check has successfully passed without issue.
    OpenChecksStatusPassed,
    /// There were issues found, but they are not deemed failures. This can be
    /// treated the same as a pass.
    OpenChecksStatusWarning,
    /// The check found an issue that caused it to fail. A validation system
    /// should block the process following the validations to have the issue
    /// fixed, unless the result allows skipping the check.
    OpenChecksStatusFailed,
    /// There was an issue with a check or runner itself. For example, code that
    /// the check depends on has an error, or the check is otherwise invalid.
    /// If a validation process finds a result with this status, then the
    /// process should not let the next process after run at all until the check
    /// has been fixed by a developer.
    OpenChecksStatusSystemError,
}

impl std::convert::From<base_openchecks::Status> for OpenChecksStatus {
    fn from(status: base_openchecks::Status) -> Self {
        match status {
            base_openchecks::Status::Pending => Self::OpenChecksStatusPending,
            base_openchecks::Status::Skipped => Self::OpenChecksStatusSkipped,
            base_openchecks::Status::Passed => Self::OpenChecksStatusPassed,
            base_openchecks::Status::Warning => Self::OpenChecksStatusWarning,
            base_openchecks::Status::Failed => Self::OpenChecksStatusFailed,
            base_openchecks::Status::SystemError => Self::OpenChecksStatusSystemError,
        }
    }
}

impl std::convert::From<OpenChecksStatus> for base_openchecks::Status {
    fn from(status: OpenChecksStatus) -> Self {
        match status {
            OpenChecksStatus::OpenChecksStatusPending => Self::Pending,
            OpenChecksStatus::OpenChecksStatusSkipped => Self::Skipped,
            OpenChecksStatus::OpenChecksStatusPassed => Self::Passed,
            OpenChecksStatus::OpenChecksStatusWarning => Self::Warning,
            OpenChecksStatus::OpenChecksStatusFailed => Self::Failed,
            OpenChecksStatus::OpenChecksStatusSystemError => Self::SystemError,
        }
    }
}

/// Return if a check is waiting to be run.
///
/// # Safety
///
/// The status must not be a null pointer.
#[no_mangle]
pub unsafe extern "C" fn openchecks_status_is_pending(status: *const OpenChecksStatus) -> bool {
    let status = match unsafe { status.as_ref() } {
        Some(s) => s,
        None => panic!("openchecks_status_is_pending received a null pointer."),
    };
    let status: base_openchecks::Status = (*status).into();
    status.is_pending()
}

/// Return if a check has passed.
///
/// # Safety
///
/// The status must not be a null pointer.
#[no_mangle]
pub unsafe extern "C" fn openchecks_status_has_passed(status: *const OpenChecksStatus) -> bool {
    let status = match unsafe { status.as_ref() } {
        Some(s) => s,
        None => panic!("openchecks_status_has_passed received a null pointer."),
    };
    let status: base_openchecks::Status = (*status).into();
    status.has_passed()
}

/// Return if a check has failed.
///
/// # Safety
///
/// The status must not be a null pointer.
#[no_mangle]
pub unsafe extern "C" fn openchecks_status_has_failed(status: *const OpenChecksStatus) -> bool {
    let status = match unsafe { status.as_ref() } {
        Some(s) => s,
        None => panic!("openchecks_status_has_failed received a null pointer."),
    };
    let status: base_openchecks::Status = (*status).into();
    status.has_failed()
}
