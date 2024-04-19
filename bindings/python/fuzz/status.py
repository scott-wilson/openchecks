# ruff: noqa: D103,D100,S101

from __future__ import annotations

import atheris
import checks
import hypothesis
from hypothesis import strategies


@hypothesis.given(
    status=strategies.sampled_from(
        [
            checks.Status.Pending,
            checks.Status.Skipped,
            checks.Status.Passed,
            checks.Status.Warning,
            checks.Status.Failed,
            checks.Status.SystemError,
        ]
    ),
)
@atheris.instrument_func
def fuzz(
    status: checks.Status,
) -> None:
    assert status.is_pending() == (status == checks.Status.Pending)
    assert status.has_passed() == (
        status in [checks.Status.Passed, checks.Status.Warning]
    )
    assert status.has_failed() == (
        status in [checks.Status.Failed, checks.Status.SystemError]
    )


if __name__ == "__main__":
    import sys

    atheris.Setup(sys.argv, atheris.instrument_func(fuzz.hypothesis.fuzz_one_input))
    atheris.Fuzz()
