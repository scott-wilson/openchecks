# ruff: noqa: D103,D100,S101

from __future__ import annotations

from typing import TYPE_CHECKING

import atheris
import hypothesis
import pychecks
from hypothesis import strategies

if TYPE_CHECKING:  # pragma: no cover
    from typing import List, Optional


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
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(pychecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
    error=strategies.one_of(strategies.none(), strategies.builds(Exception)),
)
def fuzz(
    status: pychecks.Status,
    message: str,
    items: Optional[List[pychecks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
    error: Optional[BaseException],
) -> None:
    result = pychecks.CheckResult(status, message, items, can_fix, can_skip, error)
    _validate(result, status, message, items, can_fix, can_skip, error)

    result = pychecks.CheckResult.passed(message, items, can_fix, can_skip)
    _validate(result, pychecks.Status.Passed, message, items, can_fix, can_skip, None)

    result = pychecks.CheckResult.skipped(message, items, can_fix, can_skip)
    _validate(result, pychecks.Status.Skipped, message, items, can_fix, can_skip, None)

    result = pychecks.CheckResult.warning(message, items, can_fix, can_skip)
    _validate(result, pychecks.Status.Warning, message, items, can_fix, can_skip, None)

    result = pychecks.CheckResult.failed(message, items, can_fix, can_skip)
    _validate(result, pychecks.Status.Failed, message, items, can_fix, can_skip, None)


def _validate(
    result: pychecks.CheckResult[int],
    status: pychecks.Status,
    message: str,
    items: Optional[List[pychecks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
    error: Optional[BaseException],
) -> None:
    assert result.status() == status
    assert result.message() == message

    if items is None:
        assert result.items() is None
    else:
        result_items = result.items()

        assert result_items == items

    if status == pychecks.Status.SystemError:
        assert result.can_fix() is False
    else:
        assert result.can_fix() == can_fix

    if status == pychecks.Status.SystemError:
        assert result.can_skip() is False
    else:
        assert result.can_skip() == can_skip

    error_result = result.error()

    if error is None:
        assert error_result is None
    else:
        assert isinstance(error_result, pychecks.CheckError)
        assert str(error_result) == str(error)


if __name__ == "__main__":
    import sys

    atheris.Setup(sys.argv, atheris.instrument_func(fuzz.hypothesis.fuzz_one_input))
    atheris.Fuzz()
