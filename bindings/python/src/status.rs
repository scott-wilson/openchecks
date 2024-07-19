use pyo3::prelude::*;

/// The status enum represents a result status.
///
/// - Pending: The check is waiting to run. A check should not return this
///   status, but instead this can be used by a user interface to let a user
///   know that the check is ready to run.
/// - Skipped: The check has been skipped. A check might return this to let the
///   user know that an element it depends on is invalid (such as a file
///   doesn't) exist, or a check scheduler may make child checks return this
///   status if a check fails.
/// - Passed: The check has successfully passed without issue.
/// - Warning: There were issues found, but they are not deemed failures. This
///   can be treated the same as a pass.
/// - Failed: The check found an issue that caused it to fail. A validation
///   system should block the process following the validations to have the
///   issue fixed, unless the result allows skipping the check.
/// - SystemError: There was an issue with a check or runner itself. For
///   example, code that the check depends on has an error, or the check is
///   otherwise invalid. If a validation process finds a result with this
///   status, then the process should not let the next process after run at all
///   until the check has been fixed by a developer.
#[pyclass]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Status {
    /// The check is waiting to run. A check should not return this status, but
    /// instead this can be used by a user interface to let a user know that the
    /// check is ready to run.
    Pending,
    /// The check has been skipped. A check might return this to let the user
    /// know that an element it depends on is invalid (such as a file doesn't)
    /// exist, or a check scheduler may make child checks return this status if
    /// a check fails.
    Skipped,
    /// The check has successfully passed without issue.
    Passed,
    /// There were issues found, but they are not deemed failures. This can be
    /// treated the same as a pass.
    Warning,
    /// The check found an issue that caused it to fail. A validation system
    /// should block the process following the validations to have the issue
    /// fixed, unless the result allows skipping the check.
    Failed,
    /// There was an issue with a check or runner itself. For example, code that
    /// the check depends on has an error, or the check is otherwise invalid.
    /// If a validation process finds a result with this status, then the
    /// process should not let the next process after run at all until the check
    /// has been fixed by a developer.
    SystemError,
}

impl std::convert::From<base_openchecks::Status> for Status {
    fn from(status: base_openchecks::Status) -> Self {
        match status {
            base_openchecks::Status::Pending => Self::Pending,
            base_openchecks::Status::Skipped => Self::Skipped,
            base_openchecks::Status::Passed => Self::Passed,
            base_openchecks::Status::Warning => Self::Warning,
            base_openchecks::Status::Failed => Self::Failed,
            base_openchecks::Status::SystemError => Self::SystemError,
        }
    }
}

impl std::convert::From<Status> for base_openchecks::Status {
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
    /// is_pending(self) -> bool
    ///
    /// Return if a check is waiting to be run.
    ///
    /// Returns:
    ///     bool: Whether the check is waiting to run.
    pub(crate) fn is_pending(&self) -> bool {
        let status: base_openchecks::Status = (*self).into();
        status.is_pending()
    }

    /// has_passed(self) -> bool
    ///
    /// Return if a check has passed.
    ///
    /// Returns:
    ///     bool: Whether the check has passed or not.
    pub(crate) fn has_passed(&self) -> bool {
        let status: base_openchecks::Status = (*self).into();
        status.has_passed()
    }

    /// has_failed(self) -> bool
    ///
    /// Return if a check has failed.
    ///
    /// Returns:
    ///     bool: Whether the check has failed or not.
    pub(crate) fn has_failed(&self) -> bool {
        let status: base_openchecks::Status = (*self).into();
        status.has_failed()
    }
}
