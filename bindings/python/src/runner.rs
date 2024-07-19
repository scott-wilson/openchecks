use pyo3::prelude::*;

use crate::{check_wrapper::AsyncCheckWrapper, check_wrapper::CheckWrapper, result::CheckResult};

#[pyfunction]
pub(crate) fn run(py: Python<'_>, check: PyObject) -> PyResult<CheckResult> {
    if !check.as_ref(py).is_instance_of::<crate::BaseCheck>() {
        return CheckResult::new(
            py,
            crate::Status::SystemError,
            "Check is not an instance of BaseCheck",
            None,
            false,
            false,
            Some(crate::CheckError::new_err("Check is not an instance of BaseCheck").to_object(py)),
        );
    }

    let check = CheckWrapper::new(check);
    let result = base_openchecks::run(&check);

    Ok(result.into())
}

#[pyfunction]
pub(crate) fn auto_fix(py: Python<'_>, check: PyObject) -> PyResult<CheckResult> {
    if !check.as_ref(py).is_instance_of::<crate::BaseCheck>() {
        return CheckResult::new(
            py,
            crate::Status::SystemError,
            "Check is not an instance of BaseCheck",
            None,
            false,
            false,
            Some(crate::CheckError::new_err("Check is not an instance of BaseCheck").to_object(py)),
        );
    }
    let mut check = CheckWrapper::new(check);
    let result = base_openchecks::auto_fix(&mut check);

    Ok(result.into())
}

#[pyfunction]
pub(crate) fn async_run(py: Python<'_>, check: PyObject) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let type_check_result = Python::with_gil(|py| {
            if !check.as_ref(py).is_instance_of::<crate::AsyncBaseCheck>() {
                Some(CheckResult::new(
                    py,
                    crate::Status::SystemError,
                    "Check is not an instance of AsyncBaseCheck",
                    None,
                    false,
                    false,
                    Some(
                        crate::CheckError::new_err("Check is not an instance of BaseCheck")
                            .to_object(py),
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

#[pyfunction]
pub(crate) fn async_auto_fix(py: Python<'_>, check: PyObject) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let type_check_result = Python::with_gil(|py| {
            if !check.as_ref(py).is_instance_of::<crate::AsyncBaseCheck>() {
                Some(CheckResult::new(
                    py,
                    crate::Status::SystemError,
                    "Check is not an instance of AsyncBaseCheck",
                    None,
                    false,
                    false,
                    Some(
                        crate::CheckError::new_err("Check is not an instance of BaseCheck")
                            .to_object(py),
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
