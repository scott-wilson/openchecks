from __future__ import annotations

from typing import TYPE_CHECKING
import pychecks

if TYPE_CHECKING:  # pragma: no cover
    pass


def test_check_passed_success():
    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.passed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == pychecks.CheckHint.all()

    result = check.check()
    assert result.status() == pychecks.Status.Passed
    assert result.message() == "test"


def test_check_failed_success():
    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.failed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == pychecks.CheckHint.all()

    result = check.check()
    assert result.status() == pychecks.Status.Failed
    assert result.message() == "test"


def test_check_auto_fix_success():
    class MockCheck(pychecks.BaseCheck):
        def __init__(self) -> None:
            self._value = 1

        def check(self) -> pychecks.CheckResult[int]:
            if self._value != 0:
                return pychecks.CheckResult.failed(
                    "failed", [pychecks.Item(self._value)], can_fix=True
                )

            return pychecks.CheckResult.passed("passed", [pychecks.Item(self._value)])

        def auto_fix(self) -> None:
            self._value = 0

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = check.check()
    assert result.status() == pychecks.Status.Failed
    assert result.items() == [pychecks.Item(1)]

    check.auto_fix()
    result = check.check()
    assert result.status() == pychecks.Status.Passed
    assert result.items() == [pychecks.Item(0)]
