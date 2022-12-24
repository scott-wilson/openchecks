#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CChecksStatus {
    CChecksStatusPending,
    CChecksStatusSkipped,
    CChecksStatusPassed,
    CChecksStatusWarning,
    CChecksStatusFailed,
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

impl std::convert::Into<checks::Status> for CChecksStatus {
    fn into(self) -> checks::Status {
        match self {
            Self::CChecksStatusPending => checks::Status::Pending,
            Self::CChecksStatusSkipped => checks::Status::Skipped,
            Self::CChecksStatusPassed => checks::Status::Passed,
            Self::CChecksStatusWarning => checks::Status::Warning,
            Self::CChecksStatusFailed => checks::Status::Failed,
            Self::CChecksStatusSystemError => checks::Status::SystemError,
        }
    }
}

#[no_mangle]
pub extern "C" fn cchecks_status_is_pending(status: &CChecksStatus) -> bool {
    let status: checks::Status = (*status).into();
    status.is_pending()
}

#[no_mangle]
pub extern "C" fn cchecks_status_has_passed(status: &CChecksStatus) -> bool {
    let status: checks::Status = (*status).into();
    status.has_passed()
}

#[no_mangle]
pub extern "C" fn cchecks_status_has_failed(status: &CChecksStatus) -> bool {
    let status: checks::Status = (*status).into();
    status.has_failed()
}
