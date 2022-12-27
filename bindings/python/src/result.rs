use crate::{Item, Status};
use pyo3::exceptions::PyBaseException;
use pyo3::prelude::*;

/// CheckResult(status: Status, message: str, items: Optional[List[Item[T]]] = None, can_fix: bool = False, can_skip: bool = False, error: Optional[BaseException] = None)
///
/// A check result contains all of the information needed to know the status of
/// a check.
///
/// It contains useful information such as...
///
/// - Status: A machine readable value that can be used to quickly tell whether
///   the test passed, failed, or is pending.
/// - Message: A human readable description of the status. If the status failed,
///   this should contain information on what happened, and how to fix the
///   issue.
/// - Items: An iterable of items that caused the result. For example, if a
///   check that validates if objects are named correctly failed, then the items
///   would include the offending objects.
/// - Can fix: Whether the check can be fixed or not. For example, if a check
///   requires textures to be no larger than a certain size, includes a method
///   to resize the textures, and failed, the result could be marked as fixable
///   so the user could press an "auto-fix" button in a user interface to resize
///   the textures.
/// - Can skip: Usually, a validation system should not let any checks that
///   failed to go forward with, for example, publishing an asset. Sometimes a
///   studio might decide that the error isn't critical enough to always fail if
///   a supervisor approves the fail to pass through.
/// - Error: If the status is Status.SystemError, then it may also contain the
///   error that caused the result. Other statuses shouldn't contain an error.
/// - Check duration: A diagnostic tool that could be exposed in a user
///   interface to let the user know how long it took to run the check.
/// - Fix duration: A diagnostic tool that could be exposed in a user
///   interface to let the user know how long it took to run the auto-fix.
///
/// It is suggested to use one of the other constructor methods such as
/// :code:`CheckResult.passed` for convenience.
///
/// Args:
///     status (Status): The status for the check.
///     message (str): The human readable description of the status.
///     items (Optional[List[Item[T]]]): The items that caused the result.
///     can_fix (bool): Whether the check can be fixed or not.
///     can_skip (bool): Whether the check can be skipped or not.
///     error (Optional[BaseException]): The error for the status.
#[pyclass]
#[derive(Debug)]
pub(crate) struct CheckResult {
    inner: checks::CheckResult<crate::Item, Vec<crate::Item>>,
    error: Option<Py<PyBaseException>>,
    check_duration: std::time::Duration,
    fix_duration: std::time::Duration,
}

#[pymethods]
impl CheckResult {
    #[new]
    #[args(items = "None", can_fix = "false", can_skip = "false", error = "None")]
    pub(crate) fn new(
        status: Status,
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
        error: Option<Py<PyBaseException>>,
    ) -> Self {
        let inner =
            checks::CheckResult::new(status.into(), message, items, can_fix, can_skip, None);
        Self {
            inner,
            error,
            check_duration: std::time::Duration::ZERO,
            fix_duration: std::time::Duration::ZERO,
        }
    }

    /// passed(message: str, items: Optional[List[Item[T]]], can_fix: bool, can_skip: bool) -> CheckResult
    ///
    /// Create a new result that passed a check.
    ///
    /// Args:
    ///     message (str): The human readable description of the status.
    ///     items (Optional[List[Item[T]]]): The items that caused the result.
    ///     can_fix (bool): Whether the check can be fixed or not.
    ///     can_skip (bool): Whether the check can be skipped or not.
    ///
    /// Returns:
    ///     CheckResult: The passed result.
    #[staticmethod]
    #[args(items = "None", can_fix = "false", can_skip = "false")]
    pub(crate) fn passed(
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        let inner = checks::CheckResult::new_passed(message, items, can_fix, can_skip);

        Self {
            inner,
            error: None,
            check_duration: std::time::Duration::ZERO,
            fix_duration: std::time::Duration::ZERO,
        }
    }

    /// skipped(message: str, items: Optional[List[Item[T]]], can_fix: bool, can_skip: bool) -> CheckResult
    ///
    /// Create a new result that skipped a check.
    ///
    /// Args:
    ///     message (str): The human readable description of the status.
    ///     items (Optional[List[Item[T]]]): The items that caused the result.
    ///     can_fix (bool): Whether the check can be fixed or not.
    ///     can_skip (bool): Whether the check can be skipped or not.
    ///
    /// Returns:
    ///     CheckResult: The skipped result.
    #[staticmethod]
    #[args(items = "None", can_fix = "false", can_skip = "false")]
    pub(crate) fn skipped(
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        let inner = checks::CheckResult::new_skipped(message, items, can_fix, can_skip);

        Self {
            inner,
            error: None,
            check_duration: std::time::Duration::ZERO,
            fix_duration: std::time::Duration::ZERO,
        }
    }

    /// warning(message: str, items: Optional[List[Item[T]]], can_fix: bool, can_skip: bool) -> CheckResult
    ///
    /// Create a new result that passed a check, but with a warning.
    ///
    /// Warnings should be considered as passes, but with notes saying that
    /// there *may* be an issue. For example, textures could be any resolution,
    /// but anything over 4096x4096 could be marked as a potential performance
    /// issue.
    ///
    /// Args:
    ///     message (str): The human readable description of the status.
    ///     items (Optional[List[Item[T]]]): The items that caused the result.
    ///     can_fix (bool): Whether the check can be fixed or not.
    ///     can_skip (bool): Whether the check can be skipped or not.
    ///
    /// Returns:
    ///     CheckResult: The passed with a warning result.
    #[staticmethod]
    #[args(items = "None", can_fix = "false", can_skip = "false")]
    pub(crate) fn warning(
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        let inner = checks::CheckResult::new_warning(message, items, can_fix, can_skip);

        Self {
            inner,
            error: None,
            check_duration: std::time::Duration::ZERO,
            fix_duration: std::time::Duration::ZERO,
        }
    }

    /// failed(message: str, items: Optional[List[Item[T]]], can_fix: bool, can_skip: bool) -> CheckResult
    ///
    /// Create a new result that failed a check.
    ///
    /// Failed checks in a validation system should not let the following
    /// process continue forward unless the check can be skipped/overridden by a
    /// supervisor, or is fixed and later passes, or passes with a warning.
    ///
    /// Args:
    ///     message (str): The human readable description of the status.
    ///     items (Optional[List[Item[T]]]): The items that caused the result.
    ///     can_fix (bool): Whether the check can be fixed or not.
    ///     can_skip (bool): Whether the check can be skipped or not.
    ///
    /// Returns:
    ///     CheckResult: The failed result.
    #[staticmethod]
    #[args(items = "None", can_fix = "false", can_skip = "false")]
    pub(crate) fn failed(
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        let inner = checks::CheckResult::new_failed(message, items, can_fix, can_skip);

        Self {
            inner,
            error: None,
            check_duration: std::time::Duration::ZERO,
            fix_duration: std::time::Duration::ZERO,
        }
    }

    /// status(self) -> Status
    ///
    /// The status of the result.
    ///
    /// Returns:
    ///     Status: The result status.
    pub(crate) fn status(&self) -> Status {
        (*self.inner.status()).into()
    }

    /// message(self) -> str
    ///
    /// A human readable message for the result.
    ///
    /// If a check has issues, then this should include information about what
    /// happened and how to fix the issue.
    ///
    /// Returns:
    ///     str: The result message.
    pub(crate) fn message(&self) -> &str {
        self.inner.message()
    }

    /// items(self) -> Optional[List[Item[T]]]
    ///
    /// The items that caused the result.
    ///
    /// Returns:
    ///     Optional[List[Item[T]]]: The items that caused the result.
    pub(crate) fn items(&self, _py: Python<'_>) -> Option<Vec<Item>> {
        self.inner.items().as_ref().map(|items| items.to_vec())
    }

    /// can_fix(self) -> bool
    ///
    /// Whether the result can be fixed or not.
    ///
    /// If the status is :code:`Status.SystemError`, then the check can
    /// **never** be fixed without fixing the issue with the validation system.
    ///
    /// Returns:
    ///     bool: Whether the check can be fixed or not.
    pub(crate) fn can_fix(&self) -> bool {
        self.inner.can_fix()
    }

    /// can_skip(self) -> bool
    ///
    /// Whether the result can be skipped or not.
    ///
    /// A result should only be skipped if the studio decides that letting the
    /// failed check pass will not cause serious issues to the next department.
    /// Also, it is recommended that check results are not skipped unless a
    /// supervisor overrides the skip.
    ///
    /// If the status is :code:`Status.SystemError`, then the check can
    /// **never** be skipped without fixing the issue with the validation
    /// system.
    pub(crate) fn can_skip(&self) -> bool {
        self.inner.can_skip()
    }

    /// error(self) -> Optional[BaseException]
    ///
    /// The error that caused the result.
    ///
    /// This only really applies to the
    /// :code:`Status.SystemError` status. Other results should not include the
    /// error object.
    ///
    /// Returns:
    ///     Optional[BaseException]: The error for the status.
    pub(crate) fn error<'a>(&'a self, py: Python<'a>) -> Option<&'a PyBaseException> {
        match &self.error {
            Some(err) => Some(err.as_ref(py)),
            None => None,
        }
    }

    /// check_duration(self) -> float
    ///
    /// The duration of a check.
    ///
    /// This is not settable outside of the check runner. It can be exposed to a
    /// user to let them know how long a check took to run, or be used as a
    /// diagnostics tool to improve check performance.
    ///
    /// Returns:
    ///     float: The check duration.
    pub(crate) fn check_duration(&self) -> f64 {
        self.check_duration.as_secs_f64()
    }

    /// fix_duration(self) -> float
    ///
    /// The duration of an auto-fix.
    ///
    /// This is not settable outside of the auto-fix runner. It can be exposed
    /// to a user to let them know how long an auto-fix took to run, or be used
    /// as a diagnostics tool to improve check performance.
    ///
    /// Returns:
    ///     float: The auto-fix duration.
    pub(crate) fn fix_duration(&self) -> f64 {
        self.fix_duration.as_secs_f64()
    }

    pub(crate) fn _set_check_duration(&mut self, duration: f64) {
        self.check_duration = std::time::Duration::from_secs_f64(duration)
    }

    pub(crate) fn _set_fix_duration(&mut self, duration: f64) {
        self.fix_duration = std::time::Duration::from_secs_f64(duration)
    }
}
