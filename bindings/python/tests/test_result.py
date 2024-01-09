from __future__ import annotations

from typing import TYPE_CHECKING

import hypothesis
from hypothesis import strategies

import pychecks

if TYPE_CHECKING:
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
def test_check_result_success(
    status: pychecks.Status,
    message: str,
    items: Optional[List[pychecks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
    error: Optional[BaseException],
):
    result = pychecks.CheckResult(status, message, items, can_fix, can_skip, error)

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


@hypothesis.given(
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(pychecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
    error=strategies.one_of(strategies.none(), strategies.builds(Exception)),
)
def test_check_result_skipped_success(
    message: str,
    items: Optional[List[pychecks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
    error: Optional[BaseException],
):
    status = pychecks.Status.Skipped
    result = pychecks.CheckResult.skipped(message, items, can_fix, can_skip)

    assert result.status() == status
    assert result.message() == message

    if items is None:
        assert result.items() is None
    else:
        result_items = result.items()

        assert result_items == items

    assert result.can_fix() == can_fix
    assert result.can_skip() == can_skip
    assert result.error() is None


@hypothesis.given(
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(pychecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
    error=strategies.one_of(strategies.none(), strategies.builds(Exception)),
)
def test_check_result_passed_success(
    message: str,
    items: Optional[List[pychecks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
    error: Optional[BaseException],
):
    status = pychecks.Status.Passed
    result = pychecks.CheckResult.passed(message, items, can_fix, can_skip)

    assert result.status() == status
    assert result.message() == message

    if items is None:
        assert result.items() is None
    else:
        result_items = result.items()

        assert result_items == items

    assert result.can_fix() == can_fix
    assert result.can_skip() == can_skip
    assert result.error() is None


@hypothesis.given(
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(pychecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
    error=strategies.one_of(strategies.none(), strategies.builds(Exception)),
)
def test_check_result_skipped_success(
    message: str,
    items: Optional[List[pychecks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
    error: Optional[BaseException],
):
    status = pychecks.Status.Skipped
    result = pychecks.CheckResult.skipped(message, items, can_fix, can_skip)

    assert result.status() == status
    assert result.message() == message

    if items is None:
        assert result.items() is None
    else:
        result_items = result.items()

        assert result_items == items

    assert result.can_fix() == can_fix
    assert result.can_skip() == can_skip
    assert result.error() is None


@hypothesis.given(
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(pychecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
    error=strategies.one_of(strategies.none(), strategies.builds(Exception)),
)
def test_check_result_warning_success(
    message: str,
    items: Optional[List[pychecks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
    error: Optional[BaseException],
):
    status = pychecks.Status.Warning
    result = pychecks.CheckResult.warning(message, items, can_fix, can_skip)

    assert result.status() == status
    assert result.message() == message

    if items is None:
        assert result.items() is None
    else:
        result_items = result.items()

        assert result_items == items

    assert result.can_fix() == can_fix
    assert result.can_skip() == can_skip
    assert result.error() is None


@hypothesis.given(
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(pychecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
    error=strategies.one_of(strategies.none(), strategies.builds(Exception)),
)
def test_check_result_failed_success(
    message: str,
    items: Optional[List[pychecks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
    error: Optional[BaseException],
):
    status = pychecks.Status.Failed
    result = pychecks.CheckResult.failed(message, items, can_fix, can_skip)

    assert result.status() == status
    assert result.message() == message

    if items is None:
        assert result.items() is None
    else:
        result_items = result.items()

        assert result_items == items

    assert result.can_fix() == can_fix
    assert result.can_skip() == can_skip
    assert result.error() is None
