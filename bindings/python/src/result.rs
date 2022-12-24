use crate::{Item, Status};
use pyo3::exceptions::PyBaseException;
use pyo3::prelude::*;

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

    pub(crate) fn status(&self) -> Status {
        (*self.inner.status()).into()
    }

    pub(crate) fn message(&self) -> &str {
        self.inner.message()
    }

    pub(crate) fn items(&self, _py: Python<'_>) -> Option<Vec<Item>> {
        self.inner.items().as_ref().map(|items| items.to_vec())
    }

    pub(crate) fn can_fix(&self) -> bool {
        self.inner.can_fix()
    }

    pub(crate) fn can_skip(&self) -> bool {
        self.inner.can_skip()
    }

    pub(crate) fn error<'a>(&'a self, py: Python<'a>) -> Option<&'a PyBaseException> {
        match &self.error {
            Some(err) => Some(err.as_ref(py)),
            None => None,
        }
    }

    pub(crate) fn check_duration(&self) -> f64 {
        self.check_duration.as_secs_f64()
    }

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
