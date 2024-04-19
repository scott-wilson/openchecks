use pyo3::create_exception;

create_exception!(checks, CheckError, pyo3::exceptions::PyException);
