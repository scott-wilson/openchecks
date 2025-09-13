use base_openchecks::{AsyncCheck, Check, CheckMetadata};
use pyo3::{intern, prelude::*};

use crate::item_wrapper::ItemWrapper;

pub(crate) struct CheckWrapper {
    check: Py<PyAny>,
}

impl CheckMetadata for CheckWrapper {
    fn title(&self) -> std::borrow::Cow<'_, str> {
        Python::attach(|py| {
            self.check
                .call_method0(py, intern!(py, "title"))
                .unwrap()
                .extract::<String>(py)
                .unwrap()
                .into()
        })
    }

    fn description(&self) -> std::borrow::Cow<'_, str> {
        Python::attach(|py| {
            self.check
                .call_method0(py, intern!(py, "description"))
                .unwrap()
                .extract::<String>(py)
                .unwrap()
                .into()
        })
    }

    fn hint(&self) -> base_openchecks::CheckHint {
        Python::attach(|py| {
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

    fn check(&self) -> base_openchecks::CheckResult<Self::Item, Self::Items> {
        let result = Python::attach(|py| {
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
                .extract::<Option<Vec<Py<PyAny>>>>(py)?
                .map(|items| items.into_iter().map(ItemWrapper::new).collect());

            let can_fix = result
                .call_method0(py, intern!(py, "can_fix"))?
                .extract::<bool>(py)?;

            let can_skip = result
                .call_method0(py, intern!(py, "can_skip"))?
                .extract::<bool>(py)?;

            Ok::<base_openchecks::CheckResult<ItemWrapper, Vec<ItemWrapper>>, PyErr>(
                base_openchecks::CheckResult::new(status, message, items, can_fix, can_skip, None),
            )
        });
        match result {
            Ok(result) => result,
            Err(err) => base_openchecks::CheckResult::new(
                base_openchecks::Status::SystemError,
                err.to_string(),
                None,
                false,
                false,
                Some(base_openchecks::Error::new(&err.to_string())),
            ),
        }
    }

    fn auto_fix(&mut self) -> Result<(), base_openchecks::Error> {
        Python::attach(|py| {
            self.check.call_method0(py, intern!(py, "auto_fix"))?;
            Ok(())
        })
        .map_err(|err: PyErr| base_openchecks::Error::new(&err.to_string()))
    }
}

impl CheckWrapper {
    pub(crate) fn new(check: Py<PyAny>) -> Self {
        Self { check }
    }
}

pub(crate) struct AsyncCheckWrapper {
    check: Py<PyAny>,
}

impl CheckMetadata for AsyncCheckWrapper {
    fn title(&self) -> std::borrow::Cow<'_, str> {
        Python::attach(|py| {
            self.check
                .call_method0(py, intern!(py, "title"))
                .unwrap()
                .extract::<String>(py)
                .unwrap()
                .into()
        })
    }

    fn description(&self) -> std::borrow::Cow<'_, str> {
        Python::attach(|py| {
            self.check
                .call_method0(py, intern!(py, "description"))
                .unwrap()
                .extract::<String>(py)
                .unwrap()
                .into()
        })
    }

    fn hint(&self) -> base_openchecks::CheckHint {
        Python::attach(|py| {
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

    async fn async_check(&self) -> base_openchecks::CheckResult<Self::Item, Self::Items> {
        let result = match Python::attach(|py| {
            pyo3_async_runtimes::tokio::into_future(
                self.check
                    .call_method0(py, intern!(py, "async_check"))?
                    .into_bound(py),
            )
        }) {
            Ok(result) => result.await,
            Err(err) => {
                return base_openchecks::CheckResult::new(
                    base_openchecks::Status::SystemError,
                    err.to_string(),
                    None,
                    false,
                    false,
                    Some(base_openchecks::Error::new(&err.to_string())),
                );
            }
        };

        let result = Python::attach(|py| {
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
                .extract::<Option<Vec<Py<PyAny>>>>(py)?
                .map(|items| items.into_iter().map(ItemWrapper::new).collect());

            let can_fix = result
                .call_method0(py, intern!(py, "can_fix"))?
                .extract::<bool>(py)?;

            let can_skip = result
                .call_method0(py, intern!(py, "can_skip"))?
                .extract::<bool>(py)?;

            Ok::<base_openchecks::CheckResult<ItemWrapper, Vec<ItemWrapper>>, PyErr>(
                base_openchecks::CheckResult::new(status, message, items, can_fix, can_skip, None),
            )
        });
        match result {
            Ok(result) => result,
            Err(err) => base_openchecks::CheckResult::new(
                base_openchecks::Status::SystemError,
                err.to_string(),
                None,
                false,
                false,
                Some(base_openchecks::Error::new(&err.to_string())),
            ),
        }
    }

    async fn async_auto_fix(&mut self) -> Result<(), base_openchecks::Error> {
        Python::attach(|py| {
            pyo3_async_runtimes::tokio::into_future(
                self.check
                    .call_method0(py, intern!(py, "async_auto_fix"))?
                    .into_bound(py),
            )
        })
        .map_err(|err: PyErr| base_openchecks::Error::new(&err.to_string()))?
        .await
        .map_err(|err: PyErr| base_openchecks::Error::new(&err.to_string()))?;

        Ok(())
    }
}

impl AsyncCheckWrapper {
    pub(crate) fn new(check: Py<PyAny>) -> Self {
        Self { check }
    }
}
