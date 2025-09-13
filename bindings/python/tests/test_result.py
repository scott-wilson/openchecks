from __future__ import annotations

import hypothesis
from hypothesis import strategies

import openchecks


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
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(openchecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
    error=strategies.one_of(strategies.none(), strategies.builds(Exception)),
)
def test_check_result_success(  # noqa: PLR0913
    status: openchecks.Status,
    message: str,
    items: list[openchecks.Item[int]] | None,
    can_fix: bool,  # noqa: FBT001
    can_skip: bool,  # noqa: FBT001
    error: BaseException | None,
) -> None:
    result = openchecks.CheckResult(status, message, items, can_fix, can_skip, error)

    assert result.status() == status
    assert result.message() == message

    if items is None:
        assert result.items() is None
    else:
        result_items = result.items()

        assert result_items == items

    if status == openchecks.Status.SystemError:
        assert result.can_fix() is False
    else:
        assert result.can_fix() == can_fix

    if status == openchecks.Status.SystemError:
        assert result.can_skip() is False
    else:
        assert result.can_skip() == can_skip

    error_result = result.error()

    if error is None:
        assert error_result is None
    else:
        assert isinstance(error_result, openchecks.CheckError)
        assert str(error_result) == str(error)


@hypothesis.given(
    message=strategies.text(),
    items=strategies.one_of(
        strategies.none(),
        strategies.lists(strategies.builds(openchecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
)
def test_check_result_skipped_success(
    message: str,
    items: list[openchecks.Item[int]] | None,
    can_fix: bool,  # noqa: FBT001
    can_skip: bool,  # noqa: FBT001
) -> None:
    status = openchecks.Status.Skipped
    result = openchecks.CheckResult.skipped(message, items, can_fix, can_skip)

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
        strategies.lists(strategies.builds(openchecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
)
def test_check_result_passed_success(
    message: str,
    items: list[openchecks.Item[int]] | None,
    can_fix: bool,  # noqa: FBT001
    can_skip: bool,  # noqa: FBT001
) -> None:
    status = openchecks.Status.Passed
    result = openchecks.CheckResult.passed(message, items, can_fix, can_skip)

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
        strategies.lists(strategies.builds(openchecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
)
def test_check_result_warning_success(
    message: str,
    items: list[openchecks.Item[int]] | None,
    can_fix: bool,  # noqa: FBT001
    can_skip: bool,  # noqa: FBT001
) -> None:
    status = openchecks.Status.Warning
    result = openchecks.CheckResult.warning(message, items, can_fix, can_skip)

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
        strategies.lists(strategies.builds(openchecks.Item, strategies.integers())),
    ),
    can_fix=strategies.booleans(),
    can_skip=strategies.booleans(),
)
def test_check_result_failed_success(
    message: str,
    items: list[openchecks.Item[int]] | None,
    can_fix: bool,  # noqa: FBT001
    can_skip: bool,  # noqa: FBT001
) -> None:
    status = openchecks.Status.Failed
    result = openchecks.CheckResult.failed(message, items, can_fix, can_skip)

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
