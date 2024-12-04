use crate::CheckResult;
use pyo3::exceptions::PyNotImplementedError;
use pyo3::prelude::*;

/// The check hint flags contains useful information such as whether the check
/// should support auto-fixing issues.
///
/// - :code:`NONE`: The check supports no extra features. This should be
///   considered the most conservative check *feature*. For example, no
///   auto-fix, check cannot be skipped before running, etc.
/// - :code:`AUTO_FIX`: The check supports auto-fixing. This does not guarantee
///   that the auto-fix is implemented, but instead that the auto-fix should be
///   implemented.
#[pyclass]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CheckHint {
    inner: base_openchecks::CheckHint,
}

impl From<CheckHint> for base_openchecks::CheckHint {
    fn from(hint: CheckHint) -> Self {
        hint.inner
    }
}

#[pymethods]
impl CheckHint {
    /// The check supports no extra features.
    ///
    /// This should be considered the most conservative check *feature*. For
    /// example, no auto-fix, check cannot be skipped before running, etc.
    #[classattr]
    #[allow(non_snake_case)]
    pub(crate) fn NONE() -> Self {
        Self {
            inner: base_openchecks::CheckHint::NONE,
        }
    }

    /// The check supports auto-fixing.
    ///
    /// This does not guarantee that the auto-fix is implemented, but instead
    /// that the auto-fix should be implemented.
    #[classattr]
    #[allow(non_snake_case)]
    pub(crate) fn AUTO_FIX() -> Self {
        Self {
            inner: base_openchecks::CheckHint::AUTO_FIX,
        }
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    pub(crate) fn __str__(&self) -> String {
        format!("{:?}", self.inner)
    }

    pub(crate) fn __repr__(&self) -> String {
        format!("CheckHint.{:?}", self.inner)
    }

    pub(crate) fn __iter__(&self) -> CheckHintIterator {
        CheckHintIterator {
            index: 0,
            hint: self.inner,
        }
    }

    pub(crate) fn __len__(&self) -> PyResult<usize> {
        Err(PyNotImplementedError::new_err("__len__ not implemented"))
    }

    pub(crate) fn __bool__(&self) -> bool {
        !self.inner.is_empty()
    }

    pub(crate) fn __or__(&self, other: Self) -> Self {
        Self {
            inner: self.inner | other.inner,
        }
    }

    pub(crate) fn __and__(&self, other: Self) -> Self {
        Self {
            inner: self.inner & other.inner,
        }
    }

    pub(crate) fn __xor__(&self, other: Self) -> Self {
        Self {
            inner: self.inner ^ other.inner,
        }
    }

    pub(crate) fn __invert__(&self) -> Self {
        Self { inner: !self.inner }
    }

    pub(crate) fn __contains__(&self, other: Self) -> bool {
        self.inner.contains(other.inner)
    }

    /// All of the check hint flags.
    ///
    /// Returns:
    ///     CheckHint: All of the check hint flags.
    #[staticmethod]
    pub(crate) fn all() -> Self {
        Self {
            inner: base_openchecks::CheckHint::all(),
        }
    }
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CheckHintIterator {
    index: usize,
    hint: base_openchecks::CheckHint,
}

#[pymethods]
impl CheckHintIterator {
    const ITEMS: &'static [base_openchecks::CheckHint] = &[base_openchecks::CheckHint::AUTO_FIX];

    pub(crate) fn __next__(&mut self) -> Option<CheckHint> {
        if self.index > Self::ITEMS.len() {
            return None;
        }

        for item in &Self::ITEMS[self.index..] {
            if self.hint.contains(*item) {
                self.index += 1;
                return Some(CheckHint { inner: *item });
            }
        }

        None
    }
}

/// The check metadata.
///
/// This stores the information about the check that is either useful for humans
/// (the :code:`title`) and :code:`description`) or useful for systems that uses
/// the check (:code:`hint`). For example, a user interface could use the title
/// and description to render information for an artist to inform them about
/// what the check will validate and how it will fix issues (if supported). The
/// hint then could be used to render other useful information such as whether
/// the check supports automatic fixes in general, whether it could be
/// overridden by a supervisor, etc.
///
/// This should not be inherited directly. Use :code:`BaseCheck` or
/// :code:`AsyncBaseCheck` instead.
#[pyclass(subclass)]
pub(crate) struct CheckMetadata {}

#[pymethods]
impl CheckMetadata {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    pub(crate) fn new(
        #[allow(unused_variables)] args: &Bound<'_, PyAny>,
        #[allow(unused_variables)] kwargs: Option<&Bound<'_, PyAny>>,
    ) -> Self {
        Self {}
    }

    /// The human readable title for the check.
    ///
    /// User interfaces should use the title for displaying the check.
    ///
    /// Returns:
    ///     str: The title for the check.
    pub(crate) fn title(&self) -> PyResult<&str> {
        Err(PyNotImplementedError::new_err("title not implemented"))
    }

    /// The human readable description for the check.
    ///
    /// This should include information about what the check is looking for,
    /// what are the conditions for the different statuses it supports, and if
    /// there's an auto-fix, what the auto-fix will do.
    ///
    /// Returns:
    ///     str: The description for the check.
    pub(crate) fn description(&self) -> PyResult<&str> {
        Err(PyNotImplementedError::new_err(
            "description not implemented",
        ))
    }

    /// The hint gives information about what features the check supports.
    ///
    /// Returns:
    ///     CheckHint: The hint for the check.
    pub(crate) fn hint(&self) -> CheckHint {
        CheckHint::all()
    }
}

/// The base check class to be inherited from.
///
/// This is responsible for validating the input data and returning a result
/// such as pass or fail. It can also provide extra data such as what caused the
/// status (for example, the scene nodes that are named incorrectly).
///
/// If the check supports it, then the data being validated can be automatically
/// fixed.
///
/// Example:
///
///     Simple Check
///     ------------
///
///     .. testsetup::
///
///         from openchecks import CheckResult, Item, BaseCheck, Status, run
///
///     .. testcode::
///
///         class IsEvenCheck(BaseCheck):
///             def __init__(self, value: int) -> None:
///                 self.__value = value
///                 super().__init__()
///
///             def title(self) -> str:
///                 return "Is Even Check"
///
///             def description(self) -> str:
///                 return "Check if the number is even."
///
///             def check(self) -> CheckResult:
///                 if self.__value % 2 == 0:
///                     return CheckResult.passed("Number is even.")
///                 else:
///                     return CheckResult.failed("Number is not even.")
///
///         check = IsEvenCheck(2)
///         result = run(check)
///         assert result.status() == Status.Passed
///
///     Check with Automatic Fix
///     ------------------------
///
///     .. testsetup::
///
///         from openchecks import CheckResult, Item, BaseCheck, Status, auto_fix, run
///
///     .. testcode::
///
///         class IsZeroCheck(BaseCheck):
///             def __init__(self, value: int) -> None:
///                 self.__value = value
///                 super().__init__()
///
///             def title(self) -> str:
///                 return "Is Zero Check"
///
///             def description(self) -> str:
///                 return "Check if the number is zero."
///
///             def check(self) -> CheckResult:
///                 if self.__value == 0:
///                     return CheckResult.passed("Number is zero.")
///                 else:
///                     return CheckResult.failed("Number is not zero.", can_fix=True)
///
///             def auto_fix(self) -> None:
///                 self.__value = 0
///
///         check = IsZeroCheck(1)
///         result = run(check)
///         assert result.status() == Status.Failed
///
///         if result.can_fix():
///             result = auto_fix(check)
///             assert result.status() == Status.Passed
///
#[pyclass(extends = CheckMetadata, subclass)]
#[derive(Debug)]
pub(crate) struct BaseCheck {}

#[pymethods]
impl BaseCheck {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    pub(crate) fn new(
        args: &Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyAny>>,
    ) -> (Self, CheckMetadata) {
        (Self {}, CheckMetadata::new(args, kwargs))
    }

    /// Run a validation on the input data and output the result of the
    /// validation.
    ///
    /// Raises:
    ///     NotImplementedError: The check has not been implemented.
    ///
    /// Returns:
    ///     CheckResult[T]: The result of the check.
    pub(crate) fn check(&self) -> PyResult<CheckResult> {
        Err(PyNotImplementedError::new_err("check not implemented"))
    }

    /// Automatically fix the issue detected by the :code:`Check.check` method.
    ///
    /// Raises:
    ///     NotImplementedError: The automatic fix has not been implemented.
    pub(crate) fn auto_fix(&self) -> PyResult<()> {
        Err(PyNotImplementedError::new_err("auto_fix not implemented"))
    }
}

/// The base check class to be inherited from for async code.
///
/// This is responsible for validating the input data and returning a result
/// such as pass or fail. It can also provide extra data such as what caused the
/// status (for example, the scene nodes that are named incorrectly).
///
/// If the check supports it, then the data being validated can be automatically
/// fixed.
///
/// Example:
///
///     Simple Check
///     ------------
///
///     .. testsetup::
///         import asyncio
///
///         from openchecks import CheckResult, Item, AsyncBaseCheck, Status, async_run
///
///     .. testcode::
///
///         class IsEvenCheck(AsyncBaseCheck):
///             def __init__(self, value: int) -> None:
///                 self.__value = value
///                 super().__init__()
///
///             def title(self) -> str:
///                 return "Is Even Check"
///
///             def description(self) -> str:
///                 return "Check if the number is even."
///
///             async def async_check(self) -> CheckResult:
///                 if self.__value % 2 == 0:
///                     return CheckResult.passed("Number is even.")
///                 else:
///                     return CheckResult.failed("Number is not even.")
///
///         async def main():
///             check = IsEvenCheck(2)
///             result = await async_run(check)
///             assert result.status() == Status.Passed
///
///         asyncio.run(main())
///
///     Check with Automatic Fix
///     ------------------------
///
///     .. testsetup::
///
///         import asyncio
///
///         from openchecks import CheckResult, Item, AsyncBaseCheck, Status, async_auto_fix, async_run
///
///     .. testcode::
///
///         class IsZeroCheck(AsyncBaseCheck):
///             def __init__(self, value: int) -> None:
///                 self.__value = value
///                 super().__init__()
///
///             def title(self) -> str:
///                 return "Is Zero Check"
///
///             def description(self) -> str:
///                 return "Check if the number is zero."
///
///             async def async_check(self) -> CheckResult:
///                 if self.__value == 0:
///                     return CheckResult.passed("Number is zero.")
///                 else:
///                     return CheckResult.failed("Number is not zero.", can_fix=True)
///
///             async def async_auto_fix(self) -> None:
///                 self.__value = 0
///
///         async def main():
///             check = IsZeroCheck(1)
///             result = await async_run(check)
///             assert result.status() == Status.Failed
///
///             if result.can_fix():
///                 result = await async_auto_fix(check)
///                 assert result.status() == Status.Passed
///
///         asyncio.run(main())
#[pyclass(extends = CheckMetadata, subclass)]
#[derive(Debug)]
pub(crate) struct AsyncBaseCheck {}

#[pymethods]
impl AsyncBaseCheck {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    pub(crate) fn new(
        args: &Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyAny>>,
    ) -> (Self, CheckMetadata) {
        (Self {}, CheckMetadata::new(args, kwargs))
    }

    /// Run a validation on the input data and output the result of the
    /// validation.
    ///
    /// Returns:
    ///     CheckResult[T]: The result of the check.
    pub(crate) fn async_check<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py::<_, ()>(py, async {
            Err(PyNotImplementedError::new_err("check not implemented"))
        })
    }

    /// Automatically fix the issue detected by the :code:`AsyncCheck.async_check` method.
    pub(crate) fn async_auto_fix<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py::<_, ()>(py, async {
            Err(PyNotImplementedError::new_err("check not implemented"))
        })
    }
}
