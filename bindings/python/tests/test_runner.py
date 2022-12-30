from __future__ import annotations

from typing import TYPE_CHECKING
import hypothesis
from hypothesis import strategies
import pychecks
import time

if TYPE_CHECKING:
    from typing import Optional, Callable, List


def test_run_passed_success():
    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            time.sleep(0.001)
            return pychecks.CheckResult.passed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = pychecks.run(check)
    assert result.check_duration() >= 0.001
    assert result.check_duration() <= 0.1

    assert result.status() == pychecks.Status.Passed


def test_run_failed_success():
    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            time.sleep(0.001)
            return pychecks.CheckResult.failed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = pychecks.run(check)

    assert result.status() == pychecks.Status.Failed
    assert result.check_duration() >= 0.001
    assert result.check_duration() <= 0.1


def test_run_failed_check_returns_not_result():
    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            return None

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = pychecks.run(check)

    assert result.status() == pychecks.Status.SystemError


def test_run_failed_check_raises_error():
    exception = RuntimeError("test")

    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = pychecks.run(check)

    assert result.status() == pychecks.Status.SystemError
    assert result.error() == exception


def test_run_failed_check_does_not_inherit_base_check():
    check = None
    result = pychecks.run(check)

    assert result.status() == pychecks.Status.SystemError


def test_auto_fix_passed_success():
    class MockCheck(pychecks.BaseCheck):
        def __init__(self) -> None:
            self._value = 1

        def check(self) -> pychecks.CheckResult[int]:
            time.sleep(0.001)

            if self._value != 0:
                return pychecks.CheckResult.failed(
                    "failed", [pychecks.Item(self._value)], can_fix=True
                )

            return pychecks.CheckResult.passed("passed", [pychecks.Item(self._value)])

        def auto_fix(self) -> None:
            time.sleep(0.001)
            self._value = 0

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = pychecks.run(check)

    assert result.status() == pychecks.Status.Failed
    assert result.check_duration() >= 0.001
    assert result.check_duration() <= 0.1

    result = pychecks.auto_fix(check)
    assert result.status() == pychecks.Status.Passed
    assert result.check_duration() >= 0.001
    assert result.check_duration() <= 0.1
    assert result.fix_duration() >= 0.002
    assert result.fix_duration() <= 0.2


def test_auto_fix_failed_check_does_not_inherit_base_check():
    check = None
    result = pychecks.auto_fix(check)

    assert result.status() == pychecks.Status.SystemError


def test_auto_fix_failed_check_hint_not_auto_fix():
    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.passed("passed")

        def auto_fix(self) -> None:
            pass

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

        def hint(self) -> pychecks.CheckHint:
            return pychecks.CheckHint.NONE

    check = MockCheck()
    result = pychecks.auto_fix(check)

    assert result.status() == pychecks.Status.SystemError


def test_auto_fix_failed_auto_fix_raises_error():
    exception = RuntimeError("Test")

    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.passed("passed")

        def auto_fix(self) -> None:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = pychecks.auto_fix(check)

    assert result.status() == pychecks.Status.SystemError
    assert result.error() == exception
