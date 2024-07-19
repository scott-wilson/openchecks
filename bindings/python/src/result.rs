use crate::error::CheckError;
use crate::item_wrapper::ItemWrapper;
use crate::{Item, Status};
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
    inner: base_openchecks::CheckResult<ItemWrapper, Vec<ItemWrapper>>,
}

impl From<base_openchecks::CheckResult<ItemWrapper, Vec<ItemWrapper>>> for CheckResult {
    fn from(result: base_openchecks::CheckResult<ItemWrapper, Vec<ItemWrapper>>) -> Self {
        Self { inner: result }
    }
}

#[pymethods]
impl CheckResult {
    #[new]
    #[pyo3(signature = (status, message, items = None, can_fix = false, can_skip = false, error = None))]
    pub(crate) fn new(
        py: Python<'_>,
        status: Status,
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
        error: Option<PyObject>,
    ) -> PyResult<Self> {
        let items = items.map(|items| {
            items
                .into_iter()
                .map(|item| ItemWrapper::new(item.into_py(py)))
                .collect()
        });
        let error = error.map(|err| base_openchecks::Error::new(&err.to_string()));

        let inner = base_openchecks::CheckResult::new(
            status.into(),
            message,
            items,
            can_fix,
            can_skip,
            error,
        );
        Ok(Self { inner })
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
    #[pyo3(signature = (message, items = None, can_fix = false, can_skip = false))]
    pub(crate) fn passed(
        py: Python<'_>,
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        let items = items.map(|items| {
            items
                .into_iter()
                .map(|item| ItemWrapper::new(item.into_py(py)))
                .collect()
        });
        let inner = base_openchecks::CheckResult::new_passed(message, items, can_fix, can_skip);

        Self { inner }
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
    #[pyo3(signature = (message, items = None, can_fix = false, can_skip = false))]
    pub(crate) fn skipped(
        py: Python<'_>,
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        let items = items.map(|items| {
            items
                .into_iter()
                .map(|item| ItemWrapper::new(item.into_py(py)))
                .collect()
        });
        let inner = base_openchecks::CheckResult::new_skipped(message, items, can_fix, can_skip);

        Self { inner }
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
    #[pyo3(signature = (message, items = None, can_fix = false, can_skip = false))]
    pub(crate) fn warning(
        py: Python<'_>,
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        let items = items.map(|items| {
            items
                .into_iter()
                .map(|item| ItemWrapper::new(item.into_py(py)))
                .collect()
        });
        let inner = base_openchecks::CheckResult::new_warning(message, items, can_fix, can_skip);

        Self { inner }
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
    #[pyo3(signature = (message, items = None, can_fix = false, can_skip = false))]
    pub(crate) fn failed(
        py: Python<'_>,
        message: &str,
        items: Option<Vec<Item>>,
        can_fix: bool,
        can_skip: bool,
    ) -> Self {
        let items = items.map(|items| {
            items
                .into_iter()
                .map(|item| ItemWrapper::new(item.into_py(py)))
                .collect()
        });
        let inner = base_openchecks::CheckResult::new_failed(message, items, can_fix, can_skip);

        Self { inner }
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
    pub(crate) fn items(&self) -> Option<Vec<PyObject>> {
        self.inner
            .items()
            .as_ref()
            .map(|items| items.iter().map(|item| item.item().clone()).collect())
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
    pub(crate) fn error(&self) -> Option<PyErr> {
        self.inner
            .error()
            .as_ref()
            .map(|err| CheckError::new_err(err.to_string()))
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
        self.inner.check_duration().as_secs_f64()
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
        self.inner.fix_duration().as_secs_f64()
    }
}
