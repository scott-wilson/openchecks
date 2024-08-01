# ruff: noqa: D103,D100,S101

from __future__ import annotations

import atheris
import hypothesis
import openchecks
from hypothesis import strategies


@hypothesis.given(
    status=strategies.sampled_from(
        [
            openchecks.Status.Pending,
            openchecks.Status.Skipped,
            openchecks.Status.Passed,
            openchecks.Status.Warning,
            openchecks.Status.Failed,
            openchecks.Status.SystemError,
        ]
    ),
)
@atheris.instrument_func
def fuzz(
    status: openchecks.Status,
) -> None:
    assert status.is_pending() == (status == openchecks.Status.Pending)
    assert status.has_passed() == (
        status in [openchecks.Status.Passed, openchecks.Status.Warning]
    )
    assert status.has_failed() == (
        status in [openchecks.Status.Failed, openchecks.Status.SystemError]
    )


if __name__ == "__main__":
    import sys

    atheris.Setup(sys.argv, atheris.instrument_func(fuzz.hypothesis.fuzz_one_input))
    atheris.Fuzz()
