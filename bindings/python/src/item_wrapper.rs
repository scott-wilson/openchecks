use pyo3::{exceptions::PyValueError, intern, prelude::*};

#[derive(Debug)]
pub(crate) struct ItemWrapper {
    item: PyObject,
}

impl Clone for ItemWrapper {
    fn clone(&self) -> Self {
        Python::with_gil(|py| Self {
            item: self.item.clone_ref(py),
        })
    }
}

impl std::fmt::Display for ItemWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match Python::with_gil(|py| match self.item.bind(py).str() {
            Ok(result) => write!(f, "{}", result.to_string_lossy())
                .map_err(|err| PyErr::new::<PyValueError, _>(err.to_string())),
            Err(err) => Err(err),
        }) {
            Ok(_) => Ok(()),
            Err(_) => Err(std::fmt::Error),
        }
    }
}

impl std::cmp::PartialEq for ItemWrapper {
    fn eq(&self, other: &Self) -> bool {
        Python::with_gil(|py| {
            // This is a bit of a hack, but we need to convert the type to a
            // Python object.
            let self_py = self.item.bind(py);
            let other_py = other.item.bind(py);

            self_py.eq(other_py).unwrap()
        })
    }
}

impl std::cmp::PartialOrd for ItemWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Python::with_gil(|py| {
            // This is a bit of a hack, but we need to convert the type to a
            // Python object.
            let self_py = self.item.bind(py);
            let other_py = other.item.bind(py);

            Some(self_py.compare(other_py).unwrap())
        })
    }
}

impl base_openchecks::Item for ItemWrapper {
    type Value<'a>
        = PyResult<PyObject>
    where
        Self: 'a;

    fn value(&self) -> Self::Value<'_> {
        Python::with_gil(|py| self.item.call_method0(py, intern!(py, "value")))
    }
}

impl ItemWrapper {
    pub(crate) fn new(item: PyObject) -> Self {
        Self { item }
    }

    pub(crate) fn item(&self) -> &PyObject {
        &self.item
    }
}
