use std::sync::Arc;

use pyo3::{BoundObject, intern, prelude::*, types::PyString};

/// The item is a wrapper to make a result item more user interface friendly.
///
/// Result items represent the objects that caused a result. For example, if a
/// check failed because the bones in a character rig are not properly named,
/// then the items would contain the bones that are named incorrectly.
///
/// The item wrapper makes the use of items user interface friendly because it
/// implements item sorting and a string representation of the item.
///
/// Example:
///
///     .. testsetup::
///
///         from __future__ import annotations
///
///         from openchecks import Item
///
///         class SceneNode:
///             def __init__(self, name):
///                 self.__name = name
///
///             def name(self):
///                 return self.__name
///
///     .. testcode::
///
///         class SceneItem(Item):
///             def __str__(self) -> str:
///                 return self.value().name()
///
///             def __eq__(self, other: SceneItem) -> bool:
///                 return self.value().name() == other.value().name()
///
///             def __lt__(self, other: SceneItem) -> bool:
///                 return self.value().name() < other.value().name()
///
///         a = SceneItem(SceneNode("a"))
///         b = SceneItem(SceneNode("b"))
///
///         assert a != b
///         assert a < b
///         assert str(a) == "a"
///
#[pyclass(subclass)]
#[derive(Debug, Clone)]
pub(crate) struct Item {
    value: Arc<Py<PyAny>>,
    type_hint: Option<String>,
}

#[pymethods]
impl Item {
    #[new]
    #[pyo3(signature = (value, type_hint = None))]
    fn new(value: Py<PyAny>, type_hint: Option<String>) -> Self {
        Self {
            value: Arc::new(value),
            type_hint,
        }
    }

    fn __str__<'py>(&'py self, py: Python<'py>) -> PyResult<Bound<'py, PyString>> {
        self.value.bind(py).str()
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "Item({})",
            self.value.bind(py).repr()?.to_string_lossy()
        ))
    }

    fn __eq__<'py>(
        &self,
        py: Python<'py>,
        other: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented().into_bound(py))
        } else {
            let result = self
                .value
                .bind(py)
                .eq(other.call_method0(intern!(py, "value"))?)?
                .into_pyobject(py)?;

            Ok(result.into_any().into_bound())
        }
    }

    fn __ne__<'py>(
        self_: PyRef<'_, Self>,
        py: Python<'py>,
        other: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented().into_bound(py))
        } else {
            let result = self_.into_pyobject(py)?.eq(other)?;

            Ok((!result).into_pyobject(py)?.into_any().into_bound())
        }
    }

    fn __lt__<'py>(
        &self,
        py: Python<'py>,
        other: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented().into_bound(py))
        } else {
            let result = self
                .value
                .bind(py)
                .lt(other.call_method0(intern!(py, "value"))?)?
                .into_pyobject(py)?;

            Ok(result.into_any().into_bound())
        }
    }

    fn __le__<'py>(
        self_: PyRef<'_, Self>,
        py: Python<'py>,
        other: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented().into_bound(py))
        } else {
            let result = self_.into_pyobject(py)?.gt(other)?;

            Ok((!result).into_pyobject(py)?.into_any().into_bound())
        }
    }

    fn __gt__<'py>(
        self_: PyRef<'_, Self>,
        py: Python<'py>,
        other: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented().into_bound(py))
        } else {
            let result = other.into_pyobject(py)?.lt(self_)?;

            Ok(result.into_pyobject(py)?.into_any().into_bound())
        }
    }

    fn __ge__<'py>(
        self_: PyRef<'_, Self>,
        py: Python<'py>,
        other: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented().into_bound(py))
        } else {
            let result = self_.into_pyobject(py)?.lt(other)?;

            Ok((!result).into_pyobject(py)?.into_any().into_bound())
        }
    }

    /// The wrapped value
    fn value<'py>(&'py self, py: Python<'py>) -> PyResult<&'py Bound<'py, PyAny>> {
        Ok(self.value.bind(py))
    }

    /// A type hint can be used to add a hint to a system that the given type
    /// represents something else. For example, the value could be a string, but
    /// this is a scene path.
    ///
    /// A user interface could use this hint to select the item in the
    /// application.
    fn type_hint(&self) -> Option<&str> {
        match &self.type_hint {
            Some(type_hint) => Some(type_hint.as_str()),
            None => None,
        }
    }
}
