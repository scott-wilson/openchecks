from __future__ import annotations

import asyncio

import atheris
import hypothesis
from hypothesis import strategies

import openchecks


class Check(openchecks.AsyncBaseCheck):
    def __init__(  # noqa: PLR0913
        self,
        title: str,
        description: str,
        hint: openchecks.CheckHint,
        status: openchecks.Status,
        fix_status: openchecks.Status,
        message: str,
        items: list[openchecks.Item[int]] | None,
        can_fix: bool,  # noqa: FBT001
        can_skip: bool,  # noqa: FBT001
        error: BaseException | None,
    ) -> None:
        self._title = title
        self._description = description
        self._hint = hint
        self._status = status
        self._fix_status = fix_status
        self._message = message
        self._items = items
        self._can_fix = can_fix
        self._can_skip = can_skip
        self._error = error

    def title(self) -> str:
        return self._title

    def description(self) -> str:
        return self._description

    def hint(self) -> openchecks.CheckHint:
        return self._hint

    async def async_check(self) -> openchecks.CheckResult:
        return openchecks.CheckResult(
            self._status,
            self._message,
            self._items,
            self._can_fix,
            self._can_skip,
            self._error,
        )

    async def async_auto_fix(self) -> None:
        if self._error:
            raise self._error

        self._status = self._fix_status


@strategies.composite
def check_hints(draw: strategies.DrawFn) -> openchecks.CheckHint:
    hint = openchecks.CheckHint.NONE

    if draw(strategies.booleans()):
        hint |= openchecks.CheckHint.AUTO_FIX

    return hint


@hypothesis.given(
    check=strategies.builds(
        Check,
        title=strategies.text(),
        description=strategies.text(),
        hint=check_hints(),
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
        fix_status=strategies.sampled_from(
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
            strategies.lists(
                strategies.builds(
                    openchecks.Item,
                    value=strategies.integers(),
                    type_hint=strategies.one_of(strategies.none(), strategies.text()),
                )
            ),
        ),
        can_fix=strategies.booleans(),
        can_skip=strategies.booleans(),
        error=strategies.one_of(
            strategies.none(), strategies.builds(Exception, strategies.text())
        ),
    )
)
@atheris.instrument_func
def fuzz(
    check: Check,
) -> None:
    asyncio.run(_validate(check))


async def _validate(check: Check) -> None:
    assert check.title() == check._title  # noqa: SLF001
    assert check.description() == check._description  # noqa: SLF001
    assert check.hint() == check._hint  # noqa: SLF001

    result = await check.async_check()

    assert result.status() == check._status  # noqa: SLF001
    assert result.message() == check._message  # noqa: SLF001
    assert result.items() == check._items  # noqa: SLF001

    if check._error:  # noqa: SLF001
        assert isinstance(result.error(), openchecks.CheckError)

        assert str(result.error()) == str(check._error)  # noqa: SLF001
    else:
        assert result.error() is None

    if result.status() == openchecks.Status.SystemError:
        assert result.can_fix() is False
        assert result.can_skip() is False
    else:
        assert result.can_fix() == check._can_fix  # noqa: SLF001
        assert result.can_skip() == check._can_skip  # noqa: SLF001

    if result.status().has_failed() and result.can_fix():
        fix_result = await openchecks.async_auto_fix(check)

        if not check.hint() & openchecks.CheckHint.AUTO_FIX:
            assert fix_result.status() == openchecks.Status.SystemError
            assert fix_result.message() == "Check does not implement auto fix."
            assert fix_result.items() is None
            assert fix_result.error() is None
        elif fix_result.error():
            assert fix_result.status() == openchecks.Status.SystemError
            assert fix_result.message() == "Error in auto fix."
            assert fix_result.items() is None

            if check._error:  # noqa: SLF001
                assert isinstance(fix_result.error(), openchecks.CheckError)

                assert (
                    str(fix_result.error())
                    == f"{check._error.__class__.__name__}: {check._error}"  # noqa: SLF001
                )
            else:
                assert result.error() is None
        else:
            assert fix_result.status() == check._fix_status  # noqa: SLF001
            assert fix_result.message() == check._message  # noqa: SLF001
            assert fix_result.items() == check._items  # noqa: SLF001
            assert fix_result.error() is None

        if fix_result.status() == openchecks.Status.SystemError:
            assert fix_result.can_fix() is False
            assert fix_result.can_skip() is False
        else:
            assert fix_result.can_fix() == check._can_fix  # noqa: SLF001
            assert fix_result.can_skip() == check._can_skip  # noqa: SLF001


if __name__ == "__main__":
    import sys

    atheris.Setup(sys.argv, atheris.instrument_func(fuzz.hypothesis.fuzz_one_input))
    atheris.Fuzz()
