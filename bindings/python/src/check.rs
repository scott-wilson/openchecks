use crate::{CheckResult, Item};
use pyo3::exceptions::PyNotImplementedError;
use pyo3::prelude::*;
use pyo3::pyclass::CompareOp;
use std::borrow::Cow;

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CheckHint {
    inner: checks::CheckHint,
}

#[pymethods]
impl CheckHint {
    #[classattr]
    #[allow(non_snake_case)]
    pub(crate) fn NONE() -> Self {
        Self {
            inner: checks::CheckHint::NONE,
        }
    }

    #[classattr]
    #[allow(non_snake_case)]
    pub(crate) fn AUTO_FIX() -> Self {
        Self {
            inner: checks::CheckHint::AUTO_FIX,
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

    #[staticmethod]
    pub(crate) fn all() -> Self {
        Self {
            inner: checks::CheckHint::all(),
        }
    }
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CheckHintIterator {
    index: usize,
    hint: checks::CheckHint,
}

#[pymethods]
impl CheckHintIterator {
    const ITEMS: &[checks::CheckHint] = &[checks::CheckHint::AUTO_FIX];

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
#[derive(Debug)]
pub(crate) struct BaseCheck {}

impl checks::CheckMetadata for BaseCheck {
    fn title(&self) -> Cow<str> {
        unimplemented!()
    }

    fn description(&self) -> Cow<str> {
        unimplemented!()
    }
}

impl checks::Check for BaseCheck {
    type Item = Item;
    type Items = Vec<Self::Item>;

    fn check(&self) -> checks::CheckResult<Self::Item, Self::Items> {
        unimplemented!()
    }
}

#[pymethods]
impl BaseCheck {
    #[new]
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn check(&self) -> PyResult<CheckResult> {
        Err(PyNotImplementedError::new_err("check not implemented"))
    }

    pub(crate) fn auto_fix(&self) -> PyResult<()> {
        Err(PyNotImplementedError::new_err("auto_fix not implemented"))
    }

    pub(crate) fn title(&self) -> PyResult<&str> {
        Err(PyNotImplementedError::new_err("title not implemented"))
    }

    pub(crate) fn description(&self) -> PyResult<&str> {
        Err(PyNotImplementedError::new_err(
            "description not implemented",
        ))
    }

    pub(crate) fn hint(&self) -> CheckHint {
        CheckHint::all()
    }
}
