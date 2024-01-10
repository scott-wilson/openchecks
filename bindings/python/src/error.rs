use pyo3::create_exception;

create_exception!(pychecks, CheckError, pyo3::exceptions::PyException);
