use pyo3::{intern, prelude::*, types::PyString};

/// Item(value: T, type_hint: Optional[str] = None) -> None
///
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
    value: PyObject,
    type_hint: Option<String>,
}

#[pymethods]
impl Item {
    #[new]
    #[pyo3(signature = (value, type_hint = None))]
    fn new(value: PyObject, type_hint: Option<String>) -> Self {
        Self { value, type_hint }
    }

    fn __str__<'py>(&'py self, py: Python<'py>) -> PyResult<&'py PyString> {
        self.value.as_ref(py).str()
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "Item({})",
            self.value.as_ref(py).repr()?.to_string_lossy()
        ))
    }

    fn __eq__(&self, py: Python<'_>, other: &PyAny) -> PyResult<PyObject> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented())
        } else {
            Ok(self
                .value
                .as_ref(py)
                .eq(other.call_method0(intern!(py, "value"))?)?
                .into_py(py))
        }
    }

    fn __ne__(self_: PyRef<'_, Self>, py: Python<'_>, other: &PyAny) -> PyResult<PyObject> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented())
        } else {
            Ok((!self_.into_py(py).as_ref(py).eq(other)?).into_py(py))
        }
    }

    fn __lt__(&self, py: Python<'_>, other: &PyAny) -> PyResult<PyObject> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented())
        } else {
            Ok(self
                .value
                .as_ref(py)
                .lt(other.call_method0(intern!(py, "value"))?)?
                .into_py(py))
        }
    }

    fn __le__(self_: PyRef<'_, Self>, py: Python<'_>, other: &PyAny) -> PyResult<PyObject> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented())
        } else {
            Ok((!self_.into_py(py).as_ref(py).gt(other)?).into_py(py))
        }
    }

    fn __gt__(self_: PyRef<'_, Self>, py: Python<'_>, other: &PyAny) -> PyResult<PyObject> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented())
        } else {
            Ok(other.lt(self_.into_py(py))?.into_py(py))
        }
    }

    fn __ge__(self_: PyRef<'_, Self>, py: Python<'_>, other: &PyAny) -> PyResult<PyObject> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented())
        } else {
            Ok((!self_.into_py(py).as_ref(py).lt(other)?).into_py(py))
        }
    }

    /// value(self) -> T
    ///
    /// The wrapped value
    fn value<'py>(&'py self, py: Python<'py>) -> PyResult<&'py PyAny> {
        Ok(self.value.as_ref(py))
    }

    /// type_hint(self) -> Optional[str]
    ///
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
