# ruff: noqa: D103,D100,S101

from __future__ import annotations

from typing import TYPE_CHECKING

import checks
import hypothesis
from hypothesis import strategies

if TYPE_CHECKING:
    from typing import List, Optional


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
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(checks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
    error=strategies.one_of(strategies.none(), strategies.builds(Exception)),
)
def test_check_result_success(
    status: checks.Status,
    message: str,
    items: Optional[List[checks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
    error: Optional[BaseException],
) -> None:
    result = checks.CheckResult(status, message, items, can_fix, can_skip, error)

    assert result.status() == status
    assert result.message() == message

    if items is None:
        assert result.items() is None
    else:
        result_items = result.items()

        assert result_items == items

    if status == checks.Status.SystemError:
        assert result.can_fix() is False
    else:
        assert result.can_fix() == can_fix

    if status == checks.Status.SystemError:
        assert result.can_skip() is False
    else:
        assert result.can_skip() == can_skip

    error_result = result.error()

    if error is None:
        assert error_result is None
    else:
        assert isinstance(error_result, checks.CheckError)
        assert str(error_result) == str(error)


@hypothesis.given(
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(checks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
)
def test_check_result_skipped_success(
    message: str,
    items: Optional[List[checks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
) -> None:
    status = checks.Status.Skipped
    result = checks.CheckResult.skipped(message, items, can_fix, can_skip)

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
        strategies.lists(strategies.builds(checks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
)
def test_check_result_passed_success(
    message: str,
    items: Optional[List[checks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
) -> None:
    status = checks.Status.Passed
    result = checks.CheckResult.passed(message, items, can_fix, can_skip)

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
        strategies.lists(strategies.builds(checks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
)
def test_check_result_warning_success(
    message: str,
    items: Optional[List[checks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
) -> None:
    status = checks.Status.Warning
    result = checks.CheckResult.warning(message, items, can_fix, can_skip)

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
        strategies.lists(strategies.builds(checks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
)
def test_check_result_failed_success(
    message: str,
    items: Optional[List[checks.Item[int]]],
    can_fix: bool,
    can_skip: bool,
) -> None:
    status = checks.Status.Failed
    result = checks.CheckResult.failed(message, items, can_fix, can_skip)

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
