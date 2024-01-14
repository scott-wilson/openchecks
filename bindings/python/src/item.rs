use pyo3::{intern, prelude::*, types::PyString};

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

    fn value<'py>(&'py self, py: Python<'py>) -> PyResult<&'py PyAny> {
        Ok(self.value.as_ref(py))
    }

    fn type_hint(&self) -> Option<&str> {
        match &self.type_hint {
            Some(type_hint) => Some(type_hint.as_str()),
            None => None,
        }
    }
}
