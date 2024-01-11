use checks::{AsyncCheck, Check, CheckMetadata};
use pyo3::{intern, prelude::*};

use crate::item_wrapper::ItemWrapper;

pub(crate) struct CheckWrapper {
    check: PyObject,
}

impl CheckMetadata for CheckWrapper {
    fn title(&self) -> std::borrow::Cow<str> {
        Python::with_gil(|py| {
            self.check
                .call_method0(py, intern!(py, "title"))
                .unwrap()
                .extract::<String>(py)
                .unwrap()
                .into()
        })
    }

    fn description(&self) -> std::borrow::Cow<str> {
        Python::with_gil(|py| {
            self.check
                .call_method0(py, intern!(py, "description"))
                .unwrap()
                .extract::<String>(py)
                .unwrap()
                .into()
        })
    }

    fn hint(&self) -> checks::CheckHint {
        Python::with_gil(|py| {
            self.check
                .call_method0(py, intern!(py, "hint"))
                .unwrap()
                .extract::<crate::CheckHint>(py)
                .unwrap()
                .into()
        })
    }
}

impl Check for CheckWrapper {
    type Item = ItemWrapper;

    type Items = Vec<ItemWrapper>;

    fn check(&self) -> checks::CheckResult<Self::Item, Self::Items> {
        match Python::with_gil(|py| {
            let result = self.check.call_method0(py, intern!(py, "check"))?;

            let status = result
                .call_method0(py, intern!(py, "status"))?
                .extract::<crate::Status>(py)?
                .into();

            let message = result
                .call_method0(py, intern!(py, "message"))?
                .extract::<String>(py)?;

            let items = result
                .call_method0(py, intern!(py, "items"))?
                .extract::<Option<Vec<PyObject>>>(py)?
                .map(|items| items.into_iter().map(ItemWrapper::new).collect());

            let can_fix = result
                .call_method0(py, intern!(py, "can_fix"))?
                .extract::<bool>(py)?;

            let can_skip = result
                .call_method0(py, intern!(py, "can_skip"))?
                .extract::<bool>(py)?;

            Ok::<checks::CheckResult<ItemWrapper, Vec<ItemWrapper>>, PyErr>(
                checks::CheckResult::new(status, message, items, can_fix, can_skip, None),
            )
        }) {
            Ok(result) => result,
            Err(err) => checks::CheckResult::new(
                checks::Status::SystemError,
                err.to_string(),
                None,
                false,
                false,
                Some(checks::Error::new(&err.to_string())),
            ),
        }
    }

    fn auto_fix(&mut self) -> Result<(), checks::Error> {
        Python::with_gil(|py| {
            self.check.call_method0(py, intern!(py, "auto_fix"))?;
            Ok(())
        })
        .map_err(|err: PyErr| checks::Error::new(&err.to_string()))
    }
}

impl CheckWrapper {
    pub(crate) fn new(check: PyObject) -> Self {
        Self { check }
    }
}

pub(crate) struct AsyncCheckWrapper {
    check: PyObject,
}

impl CheckMetadata for AsyncCheckWrapper {
    fn title(&self) -> std::borrow::Cow<str> {
        Python::with_gil(|py| {
            self.check
                .call_method0(py, intern!(py, "title"))
                .unwrap()
                .extract::<String>(py)
                .unwrap()
                .into()
        })
    }

    fn description(&self) -> std::borrow::Cow<str> {
        Python::with_gil(|py| {
            self.check
                .call_method0(py, intern!(py, "description"))
                .unwrap()
                .extract::<String>(py)
                .unwrap()
                .into()
        })
    }

    fn hint(&self) -> checks::CheckHint {
        Python::with_gil(|py| {
            self.check
                .call_method0(py, intern!(py, "hint"))
                .unwrap()
                .extract::<crate::CheckHint>(py)
                .unwrap()
                .into()
        })
    }
}

#[async_trait::async_trait]
impl AsyncCheck for AsyncCheckWrapper {
    type Item = ItemWrapper;

    type Items = Vec<ItemWrapper>;

    async fn async_check(&self) -> checks::CheckResult<Self::Item, Self::Items> {
        let result = match Python::with_gil(|py| {
            pyo3_asyncio::tokio::into_future(
                self.check
                    .call_method0(py, intern!(py, "async_check"))?
                    .as_ref(py),
            )
        }) {
            Ok(result) => result.await,
            Err(err) => {
                return checks::CheckResult::new(
                    checks::Status::SystemError,
                    err.to_string(),
                    None,
                    false,
                    false,
                    Some(checks::Error::new(&err.to_string())),
                )
            }
        };

        match Python::with_gil(|py| {
            let result = result?;

            let status = result
                .call_method0(py, intern!(py, "status"))?
                .extract::<crate::Status>(py)?
                .into();

            let message = result
                .call_method0(py, intern!(py, "message"))?
                .extract::<String>(py)?;

            let items = result
                .call_method0(py, intern!(py, "items"))?
                .extract::<Option<Vec<PyObject>>>(py)?
                .map(|items| items.into_iter().map(ItemWrapper::new).collect());

            let can_fix = result
                .call_method0(py, intern!(py, "can_fix"))?
                .extract::<bool>(py)?;

            let can_skip = result
                .call_method0(py, intern!(py, "can_skip"))?
                .extract::<bool>(py)?;

            Ok::<checks::CheckResult<ItemWrapper, Vec<ItemWrapper>>, PyErr>(
                checks::CheckResult::new(status, message, items, can_fix, can_skip, None),
            )
        }) {
            Ok(result) => result,
            Err(err) => checks::CheckResult::new(
                checks::Status::SystemError,
                err.to_string(),
                None,
                false,
                false,
                Some(checks::Error::new(&err.to_string())),
            ),
        }
    }

    async fn async_auto_fix(&mut self) -> Result<(), checks::Error> {
        Python::with_gil(|py| {
            pyo3_asyncio::tokio::into_future(
                self.check
                    .call_method0(py, intern!(py, "async_auto_fix"))?
                    .as_ref(py),
            )
        })
        .map_err(|err: PyErr| checks::Error::new(&err.to_string()))?
        .await
        .map_err(|err: PyErr| checks::Error::new(&err.to_string()))?;

        Ok(())
    }
}

impl AsyncCheckWrapper {
    pub(crate) fn new(check: PyObject) -> Self {
        Self { check }
    }
}
