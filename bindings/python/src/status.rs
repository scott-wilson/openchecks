use pyo3::prelude::*;

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Status {
    Pending,
    Skipped,
    Passed,
    Warning,
    Failed,
    SystemError,
}

impl std::convert::From<checks::Status> for Status {
    fn from(status: checks::Status) -> Self {
        match status {
            checks::Status::Pending => Self::Pending,
            checks::Status::Skipped => Self::Skipped,
            checks::Status::Passed => Self::Passed,
            checks::Status::Warning => Self::Warning,
            checks::Status::Failed => Self::Failed,
            checks::Status::SystemError => Self::SystemError,
        }
    }
}

impl std::convert::From<Status> for checks::Status {
    fn from(status: Status) -> Self {
        match status {
            Status::Pending => Self::Pending,
            Status::Skipped => Self::Skipped,
            Status::Passed => Self::Passed,
            Status::Warning => Self::Warning,
            Status::Failed => Self::Failed,
            Status::SystemError => Self::SystemError,
        }
    }
}

#[pymethods]
impl Status {
    pub(crate) fn is_pending(&self) -> bool {
        let status: checks::Status = (*self).into();
        status.is_pending()
    }

    pub(crate) fn has_passed(&self) -> bool {
        let status: checks::Status = (*self).into();
        status.has_passed()
    }

    pub(crate) fn has_failed(&self) -> bool {
        let status: checks::Status = (*self).into();
        status.has_failed()
    }
}
