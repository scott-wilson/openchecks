use pyo3::prelude::*;

use crate::{check_wrapper::AsyncCheckWrapper, check_wrapper::CheckWrapper, result::CheckResult};

/// Run a check.
///
/// Running a check should never fail, but instead return a failure check
/// result. The run function might return a :code:`Status.SystemError` if the
/// system runs into an error that must be resolved by the team supporting and
/// implementing the checks.
///
/// Example:
///
///     .. testsetup::
///
///         from openchecks import CheckResult, Item, BaseCheck, Status, run
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
///     .. testcode::
///
///         check = IsEvenCheck(2)
///         result = run(check)
///         assert result.status() == Status.Passed
///
#[pyfunction]
pub(crate) fn run(py: Python<'_>, check: Py<PyAny>) -> PyResult<CheckResult> {
    if !check.bind(py).is_instance_of::<crate::BaseCheck>() {
        return CheckResult::new(
            py,
            crate::Status::SystemError,
            "Check is not an instance of BaseCheck",
            None,
            false,
            false,
            Some(
                crate::CheckError::new_err("Check is not an instance of BaseCheck")
                    .into_pyobject(py)?,
            ),
        );
    }

    let check = CheckWrapper::new(check);
    let result = base_openchecks::run(&check);

    Ok(result.into())
}

/// Automatically fix an issue found by a check.
///
/// This function should only be run after the :code:`run` returns a result, and
/// that result can be fixed. Otherwise, the fix might try to fix an already
/// "good" object, causing issues with the object.
///
/// The auto-fix will re-run the :code:`run` to validate that it has actually
/// fixed the issue.
///
/// This will return a result with the
/// :code:`Status.SystemError` status if the check does
/// not have the :code:`CheckHint.AUTO_FIX` flag set, or
/// an auto-fix returned an error. In the case of the latter, it will include
/// the error with the check result.
///
/// .. testsetup::
///
///     from openchecks import CheckResult, Item, BaseCheck, Status, auto_fix, run
///
///     class IsZeroCheck(BaseCheck):
///         def __init__(self, value: int) -> None:
///             self.__value = value
///             super().__init__()
///
///         def title(self) -> str:
///             return "Is Zero Check"
///
///         def description(self) -> str:
///             return "Check if the number is zero."
///
///         def check(self) -> CheckResult:
///             if self.__value == 0:
///                 return CheckResult.passed("Number is zero.")
///             else:
///                 return CheckResult.failed("Number is not zero.", can_fix=True)
///
///         def auto_fix(self) -> None:
///             self.__value = 0
///
/// .. testcode::
///
///     check = IsZeroCheck(1)
///     result = run(check)
///     assert result.status() == Status.Failed
///
///     if result.can_fix():
///         result = auto_fix(check)
///         assert result.status() == Status.Passed
#[pyfunction]
pub(crate) fn auto_fix(py: Python<'_>, check: Py<PyAny>) -> PyResult<CheckResult> {
    if !check.bind(py).is_instance_of::<crate::BaseCheck>() {
        return CheckResult::new(
            py,
            crate::Status::SystemError,
            "Check is not an instance of BaseCheck",
            None,
            false,
            false,
            Some(
                crate::CheckError::new_err("Check is not an instance of BaseCheck")
                    .into_pyobject(py)?,
            ),
        );
    }
    let mut check = CheckWrapper::new(check);
    let result = base_openchecks::auto_fix(&mut check);

    Ok(result.into())
}

/// Run a check in an async context.
///
/// Running a check should never fail, but instead return a failure check
/// result. The run function might return a :code:`Status.SystemError` if the
/// system runs into an error that must be resolved by the team supporting and
/// implementing the checks.
///
/// Example:
///
///     .. testsetup::
///
///         import asyncio
///
///         from openchecks import CheckResult, Item, AsyncBaseCheck, Status, async_run
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
///     .. testcode::
///
///         async def main():
///             check = IsEvenCheck(2)
///             result = run(check)
///             assert result.status() == Status.Passed
///
///         asyncio.run(main())
///
#[pyfunction]
pub(crate) fn async_run(py: Python<'_>, check: Py<PyAny>) -> PyResult<Bound<'_, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let type_check_result = Python::attach(|py| {
            if !check.bind(py).is_instance_of::<crate::AsyncBaseCheck>() {
                Some(CheckResult::new(
                    py,
                    crate::Status::SystemError,
                    "Check is not an instance of AsyncBaseCheck",
                    None,
                    false,
                    false,
                    Some(
                        crate::CheckError::new_err("Check is not an instance of BaseCheck")
                            .into_pyobject(py)
                            .unwrap(),
                    ),
                ))
            } else {
                None
            }
        });

        if let Some(result) = type_check_result {
            return result;
        }

        let check = AsyncCheckWrapper::new(check);

        let result: CheckResult = base_openchecks::async_run(&check).await.into();

        Ok(result)
    })
}

/// Automatically fix an issue found by a check in an async context.
///
/// This function should only be run after the :code:`async_run` returns a
/// result, and that result can be fixed. Otherwise, the fix might try to fix an
/// already "good" object, causing issues with the object.
///
/// The auto-fix will re-run the :code:`async_run` to validate that it has
/// actually fixed the issue.
///
/// This will return a result with the
/// :code:`Status.SystemError` status if the check does
/// not have the :code:`CheckHint.AUTO_FIX` flag set, or
/// an auto-fix returned an error. In the case of the latter, it will include
/// the error with the check result.
///
/// .. testsetup::
///
///     import asyncio
///
///     from openchecks import CheckResult, Item, AsyncBaseCheck, Status, async_auto_fix, async_run
///
///     class IsZeroCheck(AsyncBaseCheck):
///         def __init__(self, value: int) -> None:
///             self.__value = value
///             super().__init__()
///
///         def title(self) -> str:
///             return "Is Zero Check"
///
///         def description(self) -> str:
///             return "Check if the number is zero."
///
///         async def async_check(self) -> CheckResult:
///             if self.__value == 0:
///                 return CheckResult.passed("Number is zero.")
///             else:
///                 return CheckResult.failed("Number is not zero.", can_fix=True)
///
///         async def async_auto_fix(self) -> None:
///             self.__value = 0
///
/// .. testcode::
///
///     async def main():
///         check = IsZeroCheck(1)
///         result = run(check)
///         assert result.status() == Status.Failed
///
///         if result.can_fix():
///             result = auto_fix(check)
///             assert result.status() == Status.Passed
///
///     asyncio.run(main())
#[pyfunction]
pub(crate) fn async_auto_fix(py: Python<'_>, check: Py<PyAny>) -> PyResult<Bound<'_, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let type_check_result = Python::attach(|py| {
            if !check.bind(py).is_instance_of::<crate::AsyncBaseCheck>() {
                Some(CheckResult::new(
                    py,
                    crate::Status::SystemError,
                    "Check is not an instance of AsyncBaseCheck",
                    None,
                    false,
                    false,
                    Some(
                        crate::CheckError::new_err("Check is not an instance of BaseCheck")
                            .into_pyobject(py)
                            .unwrap(),
                    ),
                ))
            } else {
                None
            }
        });

        if let Some(result) = type_check_result {
            return result;
        }

        let mut check = AsyncCheckWrapper::new(check);

        let result: CheckResult = base_openchecks::async_auto_fix(&mut check).await.into();

        Ok(result)
    })
}
