from __future__ import annotations

import atheris
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
def fuzz(  # noqa: PLR0913
    status: openchecks.Status,
    message: str,
    items: list[openchecks.Item[int]] | None,
    can_fix: bool,  # noqa: FBT001
    can_skip: bool,  # noqa: FBT001
    error: BaseException | None,
) -> None:
    result = openchecks.CheckResult(status, message, items, can_fix, can_skip, error)
    _validate(result, status, message, items, can_fix, can_skip, error)

    result = openchecks.CheckResult.passed(message, items, can_fix, can_skip)
    _validate(result, openchecks.Status.Passed, message, items, can_fix, can_skip, None)

    result = openchecks.CheckResult.skipped(message, items, can_fix, can_skip)
    _validate(
        result, openchecks.Status.Skipped, message, items, can_fix, can_skip, None
    )

    result = openchecks.CheckResult.warning(message, items, can_fix, can_skip)
    _validate(
        result, openchecks.Status.Warning, message, items, can_fix, can_skip, None
    )

    result = openchecks.CheckResult.failed(message, items, can_fix, can_skip)
    _validate(result, openchecks.Status.Failed, message, items, can_fix, can_skip, None)


def _validate(  # noqa: PLR0913
    result: openchecks.CheckResult[int],
    status: openchecks.Status,
    message: str,
    items: list[openchecks.Item[int]] | None,
    can_fix: bool,  # noqa: FBT001
    can_skip: bool,  # noqa: FBT001
    error: BaseException | None,
) -> None:
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


if __name__ == "__main__":
    import sys

    atheris.Setup(sys.argv, atheris.instrument_func(fuzz.hypothesis.fuzz_one_input))
    atheris.Fuzz()
