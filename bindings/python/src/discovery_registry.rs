use pyo3::prelude::*;

/// The discovery registry allows checks to be discovered based on the input
/// context.
///
/// The registry accepts two functions. The query function that is responsible
/// for querying if the context is valid, and the generate function that will
/// take the context and transform it into checks to be validated against.
#[pyclass]
pub(crate) struct DiscoveryRegistry {
    plugins: Vec<(PyObject, PyObject)>,
    async_plugins: Vec<(PyObject, PyObject)>,
}

#[pymethods]
impl DiscoveryRegistry {
    /// Create a new instance of the discovery registry.
    #[new]
    fn new() -> Self {
        Self {
            plugins: Vec::new(),
            async_plugins: Vec::new(),
        }
    }

    /// Register the functions that will find the checks to be run.
    ///
    /// The query function is responsible for querying if the gather method for
    /// the registry will return the contents of the generator function. The
    /// generator function is responsible for returning a list of checks for the
    /// given context.
    pub fn register(&mut self, query: Bound<PyAny>, generator: Bound<PyAny>) {
        self.plugins.push((query.unbind(), generator.unbind()));
    }

    /// Register the functions that will find the checks to be run in async.
    ///
    /// The query function is responsible for querying if the gather method for
    /// the registry will return the contents of the generator function. The
    /// generator function is responsible for returning a list of checks for the
    /// given context.
    pub fn register_async(&mut self, query: Bound<PyAny>, generator: Bound<PyAny>) {
        self.async_plugins
            .push((query.unbind(), generator.unbind()));
    }

    /// Return the checks that should be run for the given context.
    ///
    /// If the result is `None`, then nothing was found that will return valid
    /// checks.
    ///
    /// If two query functions were to return a valid set of checks, then the
    /// first one that was registered will return the associated checks.
    pub fn gather(&self, py: Python, context: Bound<PyAny>) -> PyResult<Option<PyObject>> {
        for (query, generator) in &self.plugins {
            if query.call1(py, (&context,))?.is_truthy(py)? {
                return Ok(Some(generator.call1(py, (context,))?));
            }
        }

        Ok(None)
    }

    /// Return the async checks that should be run for the given context.
    ///
    /// If the result is `None`, then nothing was found that will return valid
    /// checks.
    ///
    /// If two query functions were to return a valid set of checks, then the
    /// first one that was registered will return the associated checks.
    pub fn gather_async(&self, py: Python, context: Bound<PyAny>) -> PyResult<Option<PyObject>> {
        for (query, generator) in &self.async_plugins {
            if query.call1(py, (&context,))?.is_truthy(py)? {
                return Ok(Some(generator.call1(py, (context,))?));
            }
        }

        Ok(None)
    }
}
