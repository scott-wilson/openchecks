# ruff: noqa: D103,D100,S101

from __future__ import annotations

import atheris
import hypothesis
import pychecks
from hypothesis import strategies


@hypothesis.given(
    status=strategies.sampled_from(
        [
            pychecks.Status.Pending,
            pychecks.Status.Skipped,
            pychecks.Status.Passed,
            pychecks.Status.Warning,
            pychecks.Status.Failed,
            pychecks.Status.SystemError,
        ]
    ),
)
@atheris.instrument_func
def fuzz(
    status: pychecks.Status,
) -> None:
    assert status.is_pending() == (status == pychecks.Status.Pending)
    assert status.has_passed() == (
        status in [pychecks.Status.Passed, pychecks.Status.Warning]
    )
    assert status.has_failed() == (
        status in [pychecks.Status.Failed, pychecks.Status.SystemError]
    )


if __name__ == "__main__":
    import sys

    atheris.Setup(sys.argv, atheris.instrument_func(fuzz.hypothesis.fuzz_one_input))
    atheris.Fuzz()
