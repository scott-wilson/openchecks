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

impl std::convert::Into<checks::Status> for Status {
    fn into(self) -> checks::Status {
        match self {
            Self::Pending => checks::Status::Pending,
            Self::Skipped => checks::Status::Skipped,
            Self::Passed => checks::Status::Passed,
            Self::Warning => checks::Status::Warning,
            Self::Failed => checks::Status::Failed,
            Self::SystemError => checks::Status::SystemError,
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
