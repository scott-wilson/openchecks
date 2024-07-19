use crate::CheckResult;
use pyo3::exceptions::PyNotImplementedError;
use pyo3::prelude::*;
use pyo3::pyclass::CompareOp;

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

    fn __richcmp__(&self, py: Python<'_>, other: &Self, op: CompareOp) -> PyObject {
        match op {
            CompareOp::Eq => (self.inner == other.inner).to_object(py),
            _ => py.NotImplemented(),
        }
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

    /// all() -> CheckHint
    ///
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

#[pyclass(subclass)]
pub(crate) struct CheckMetadata {}

#[pymethods]
impl CheckMetadata {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    pub(crate) fn new(
        #[allow(unused_variables)] args: &PyAny,
        #[allow(unused_variables)] kwargs: Option<&PyAny>,
    ) -> Self {
        Self {}
    }

    /// title(self) -> str
    ///
    /// The human readable title for the check.
    ///
    /// User interfaces should use the title for displaying the check.
    ///
    /// Returns:
    ///     str: The title for the check.
    pub(crate) fn title(&self) -> PyResult<&str> {
        Err(PyNotImplementedError::new_err("title not implemented"))
    }

    /// description(self) -> str
    ///
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

    /// hint(self) -> CheckHint
    ///
    /// The hint gives information about what features the check supports.
    ///
    /// Returns:
    ///     CheckHint: The hint for the check.
    pub(crate) fn hint(&self) -> CheckHint {
        CheckHint::all()
    }
}

/// BaseCheck
///
/// The base check to subclass.
#[pyclass(extends = CheckMetadata, subclass)]
#[derive(Debug)]
pub(crate) struct BaseCheck {}

#[pymethods]
impl BaseCheck {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    pub(crate) fn new(args: &PyAny, kwargs: Option<&PyAny>) -> (Self, CheckMetadata) {
        (Self {}, CheckMetadata::new(args, kwargs))
    }

    /// check(self) -> CheckResult[T]
    ///
    /// Run a validation on the input data and output the result of the
    /// validation.
    ///
    /// Returns:
    ///     CheckResult[T]: The result of the check.
    pub(crate) fn check(&self) -> PyResult<CheckResult> {
        Err(PyNotImplementedError::new_err("check not implemented"))
    }

    /// auto_fix(self)
    ///
    /// Automatically fix the issue detected by the :code:`Check.check` method.
    pub(crate) fn auto_fix(&self) -> PyResult<()> {
        Err(PyNotImplementedError::new_err("auto_fix not implemented"))
    }
}

/// AsyncBaseCheck
///
/// The base check to subclass.
#[pyclass(extends = CheckMetadata, subclass)]
#[derive(Debug)]
pub(crate) struct AsyncBaseCheck {}

#[pymethods]
impl AsyncBaseCheck {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    pub(crate) fn new(args: &PyAny, kwargs: Option<&PyAny>) -> (Self, CheckMetadata) {
        (Self {}, CheckMetadata::new(args, kwargs))
    }

    /// async_check(self) -> CheckResult[T]
    ///
    /// Run a validation on the input data and output the result of the
    /// validation.
    ///
    /// Returns:
    ///     CheckResult[T]: The result of the check.
    pub(crate) fn async_check<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        pyo3_asyncio::tokio::future_into_py::<_, &PyAny>(py, async {
            Err(PyNotImplementedError::new_err("check not implemented"))
        })
    }

    /// async_auto_fix(self)
    ///
    /// Automatically fix the issue detected by the :code:`AsyncCheck.async_check` method.
    pub(crate) fn async_auto_fix<'py>(&self, py: Python<'py>) -> PyResult<&'py PyAny> {
        pyo3_asyncio::tokio::future_into_py::<_, &PyAny>(py, async {
            Err(PyNotImplementedError::new_err("check not implemented"))
        })
    }
}
