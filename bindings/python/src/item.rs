use pyo3::{intern, prelude::*};

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

    fn __str__<'py>(&'py self, py: Python<'py>) -> PyResult<&'py str> {
        self.value.as_ref(py).str()?.to_str()
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("Item({})", self.value.as_ref(py).repr()?.to_str()?))
    }

    fn __eq__(&self, py: Python<'_>, other: &PyAny) -> PyResult<PyObject> {
        if !other.is_instance_of::<Self>() {
            Ok(py.NotImplemented())
        } else {
            Ok(self
                .value
                .as_ref(py)
                .eq(&other.call_method0(intern!(py, "value"))?)?
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
                .lt(&other.call_method0(intern!(py, "value"))?)?
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

// /// Item(value: T, type_hint: Optional[str] = None, debug_fn: Optional[Callable[[T], str]] = None, display_fn: Optional[Callable[[T], str]] = None, lt_fn: Optional[Callable[[T, T], bool]] = None, eq_fn: Optional[Callable[[T, T], bool]] = None)
// ///
// /// The item is a wrapper to make a result item more user interface friendly.
// ///
// /// Result items represent the objects that caused a result. For example, if a
// /// check failed because the bones in a character rig are not properly named,
// /// then the items would contain the bones that are named incorrectly.
// ///
// /// The item wrapper makes the use of items user interface friendly because it
// /// implements item sorting and a string representation of the item.
// ///
// /// Args:
// ///     value (T): The wrapped value
// ///     type_hint (Optional[str]): A hint to add extra context to the value.
// ///         For example, if the value is a string, and that string represents a
// ///         scene path, then a user interface could use that knowledge to select
// ///         the scene path in the application. Default to the type having no
// ///         meaning outside of itself.
// ///     debug_fn (Optional[Callable[[T], str]]): The debug function for the
// ///         item. Should be accessed via the :code:`repr(item)` function.
// ///         Defaults to calling :code:`repr(value)`.
// ///     display_fn (Optional[Callable[[T], str]]): The display function for the
// ///         item. Should be accessed via the :code:`str(item)` function.
// ///         Defaults to calling :code:`str(value)`.
// ///     lt_fn (Optional[Callable[[T, T], bool]]): The less than function. Should
// ///         be accessed by the :code:`item_a < item_b` operation. Defaults to
// ///         calling :code:`value_a < value_b`.
// ///     eq_fn (Optional[Callable[[T, T], bool]]): The equal function. Should be
// ///         accessed by the :code:`item_a == item_b` operation. Defaults to
// ///         calling :code:`value_a == value_b`.
// #[pyclass]
// #[derive(Debug, Clone)]
// pub(crate) struct Item {
//     value: PyObject,
//     type_hint: Option<Py<PyString>>,
//     debug_fn: PyObject,
//     display_fn: PyObject,
//     lt_fn: PyObject,
//     eq_fn: PyObject,
// }

// impl std::fmt::Display for Item {
//     fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         unimplemented!()
//     }
// }

// impl std::cmp::PartialEq for Item {
//     fn eq(&self, _other: &Self) -> bool {
//         unimplemented!()
//     }
// }

// impl std::cmp::PartialOrd for Item {
//     fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
//         unimplemented!()
//     }
// }

// impl checks::Item for Item {
//     type Value = ();

//     fn value(&self) -> Self::Value {
//         unimplemented!()
//     }
// }

// #[pymethods]
// impl Item {
//     #[new]
//     #[pyo3(signature = (
//         value,
//         type_hint = None,
//         debug_fn = None,
//         display_fn = None,
//         lt_fn = None,
//         eq_fn = None,
//     ))]
//     fn new(
//         py: Python<'_>,
//         value: PyObject,
//         type_hint: Option<Py<PyString>>,
//         debug_fn: Option<PyObject>,
//         display_fn: Option<PyObject>,
//         lt_fn: Option<PyObject>,
//         eq_fn: Option<PyObject>,
//     ) -> PyResult<Self> {
//         let debug_fn = match debug_fn {
//             Some(func) => func.extract::<PyObject>(py)?,
//             None => py.eval("repr", None, None)?.extract::<PyObject>()?,
//         };
//         let display_fn = match display_fn {
//             Some(func) => func.extract::<PyObject>(py)?,
//             None => py.eval("str", None, None)?.extract::<PyObject>()?,
//         };
//         let lt_fn = match lt_fn {
//             Some(func) => func.extract::<PyObject>(py)?,
//             None => {
//                 if value.getattr(py, intern!(py, "__lt__")).is_err() {
//                     return Err(PyErr::new::<PyAttributeError, _>(
//                         "Value does not support ordering.",
//                     ));
//                 }

//                 let locals = PyDict::new(py);

//                 py.run("import operator; func = operator.lt", None, Some(locals))?;
//                 match locals.get_item("func")? {
//                     Some(func) => func.extract::<PyObject>()?,
//                     None => return Err(PyErr::new::<PyValueError, _>("Could not find function")),
//                 }
//                 .extract::<PyObject>(py)?
//             }
//         };
//         let eq_fn = match eq_fn {
//             Some(func) => func.extract::<PyObject>(py)?,
//             None => {
//                 if value.getattr(py, intern!(py, "__eq__")).is_err() {
//                     return Err(PyErr::new::<PyAttributeError, _>(
//                         "Value does not support comparisons.",
//                     ));
//                 }

//                 let locals = PyDict::new(py);

//                 py.run("import operator; func = operator.eq", None, Some(locals))?;
//                 match locals.get_item("func")? {
//                     Some(func) => func.extract::<PyObject>()?,
//                     None => return Err(PyErr::new::<PyValueError, _>("Could not find function")),
//                 }
//                 .extract::<PyObject>(py)?
//             }
//         };

//         Ok(Self {
//             value,
//             type_hint,
//             debug_fn,
//             display_fn,
//             lt_fn,
//             eq_fn,
//         })
//     }

//     fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
//         Ok(format!(
//             "Item({})",
//             &self.debug_fn.call(py, (&self.value,), None)?
//         ))
//     }

//     fn __str__(&self, py: Python<'_>) -> PyResult<String> {
//         Ok(format!(
//             "{}",
//             self.display_fn.call(py, (&self.value,), None)?
//         ))
//     }

//     fn __richcmp__(&self, py: Python<'_>, other: &Self, op: CompareOp) -> PyResult<bool> {
//         let ordering = if self
//             .lt_fn
//             .call(py, (&self.value, &other.value), None)?
//             .is_true(py)?
//         {
//             std::cmp::Ordering::Less
//         } else if self
//             .eq_fn
//             .call(py, (&self.value, &other.value), None)?
//             .is_true(py)?
//         {
//             std::cmp::Ordering::Equal
//         } else {
//             std::cmp::Ordering::Greater
//         };

//         Ok(op.matches(ordering))
//     }

//     /// value(self) -> T
//     ///
//     /// The value that is wrapped.
//     ///
//     /// Returns:
//     ///     T: The wrapped value.
//     fn value(&self) -> &PyObject {
//         &self.value
//     }

//     /// type_hint(self) -> Optional[str]
//     ///
//     /// A type hint can be used to add a hint to a system that the given type
//     /// represents something else. For example, the value could be a string, but
//     /// this is a scene path.
//     ///
//     /// A user interface could use this hint to select the item in the
//     /// application.
//     ///
//     /// Returns:
//     ///     Optional[str]: The type hint.
//     fn type_hint<'a>(&'a self, py: Python<'a>) -> Option<&'a PyString> {
//         match &self.type_hint {
//             Some(type_hint) => Some(type_hint.as_ref(py)),
//             None => None,
//         }
//     }
// }
