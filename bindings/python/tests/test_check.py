# ruff: noqa: D103,D100,S101

from __future__ import annotations

from typing import TYPE_CHECKING

import openchecks
import pytest

if TYPE_CHECKING:  # pragma: no cover
    pass


def test_check_passed_success() -> None:
    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == openchecks.CheckHint.AUTO_FIX | openchecks.CheckHint.NONE

    result = check.check()
    assert result.status() == openchecks.Status.Passed
    assert result.message() == "test"


def test_check_failed_success() -> None:
    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.failed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == openchecks.CheckHint.AUTO_FIX | openchecks.CheckHint.NONE

    result = check.check()
    assert result.status() == openchecks.Status.Failed
    assert result.message() == "test"


def test_check_auto_fix_success() -> None:
    class MockCheck(openchecks.BaseCheck):
        def __init__(self) -> None:
            self._value = 1

        def check(self) -> openchecks.CheckResult[int]:
            if self._value != 0:
                return openchecks.CheckResult.failed(
                    "failed", [openchecks.Item(self._value)], can_fix=True
                )

            return openchecks.CheckResult.passed(
                "passed", [openchecks.Item(self._value)]
            )

        def auto_fix(self) -> None:
            self._value = 0

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = check.check()
    assert result.status() == openchecks.Status.Failed
    assert result.items() == [openchecks.Item(1)]

    check.auto_fix()
    result = check.check()
    assert result.status() == openchecks.Status.Passed
    assert result.items() == [openchecks.Item(0)]


@pytest.mark.asyncio()
async def test_check_auto_fix_failed_not_implemented() -> None:
    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()

    with pytest.raises(NotImplementedError):
        check.auto_fix()


@pytest.mark.asyncio()
async def test_async_check_passed_success() -> None:
    class MockCheck(openchecks.AsyncBaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == openchecks.CheckHint.AUTO_FIX | openchecks.CheckHint.NONE

    result = await check.async_check()
    assert result.status() == openchecks.Status.Passed
    assert result.message() == "test"


@pytest.mark.asyncio()
async def test_async_check_failed_success() -> None:
    class MockCheck(openchecks.AsyncBaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.failed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == openchecks.CheckHint.AUTO_FIX | openchecks.CheckHint.NONE

    result = await check.async_check()
    assert result.status() == openchecks.Status.Failed
    assert result.message() == "test"


@pytest.mark.asyncio()
async def test_async_check_auto_fix_success() -> None:
    class MockCheck(openchecks.AsyncBaseCheck):
        def __init__(self) -> None:
            self._value = 1

        async def async_check(self) -> openchecks.CheckResult[int]:
            if self._value != 0:
                return openchecks.CheckResult.failed(
                    "failed", [openchecks.Item(self._value)], can_fix=True
                )

            return openchecks.CheckResult.passed(
                "passed", [openchecks.Item(self._value)]
            )

        async def async_auto_fix(self) -> None:
            self._value = 0

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await check.async_check()
    assert result.status() == openchecks.Status.Failed
    assert result.items() == [openchecks.Item(1)]

    await check.async_auto_fix()
    result = await check.async_check()
    assert result.status() == openchecks.Status.Passed
    assert result.items() == [openchecks.Item(0)]


@pytest.mark.asyncio()
async def test_async_check_auto_fix_failed_not_implemented() -> None:
    class MockCheck(openchecks.AsyncBaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()

    with pytest.raises(NotImplementedError):
        await check.async_auto_fix()


@pytest.mark.asyncio()
async def test_both_check_passed_success() -> None:
    class MockCheck(openchecks.AsyncBaseCheck, openchecks.BaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            return self.check()

        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == openchecks.CheckHint.AUTO_FIX | openchecks.CheckHint.NONE

    result = await check.async_check()
    assert result.status() == openchecks.Status.Passed
    assert result.message() == "test"


@pytest.mark.asyncio()
async def test_both_check_failed_success() -> None:
    class MockCheck(openchecks.AsyncBaseCheck, openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.failed("test")

        async def async_check(self) -> openchecks.CheckResult[int]:
            return self.check()

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == openchecks.CheckHint.AUTO_FIX | openchecks.CheckHint.NONE

    result = await check.async_check()
    assert result.status() == openchecks.Status.Failed
    assert result.message() == "test"


@pytest.mark.asyncio()
async def test_both_check_auto_fix_success() -> None:
    class MockCheck(openchecks.AsyncBaseCheck, openchecks.BaseCheck):
        def __init__(self) -> None:
            self._value = 1

        def check(self) -> openchecks.CheckResult[int]:
            if self._value != 0:
                return openchecks.CheckResult.failed(
                    "failed", [openchecks.Item(self._value)], can_fix=True
                )

            return openchecks.CheckResult.passed(
                "passed", [openchecks.Item(self._value)]
            )

        async def async_check(self) -> openchecks.CheckResult[int]:
            return self.check()

        def auto_fix(self) -> None:
            self._value = 0

        async def async_auto_fix(self) -> None:
            self.auto_fix()

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await check.async_check()
    assert result.status() == openchecks.Status.Failed
    assert result.items() == [openchecks.Item(1)]

    await check.async_auto_fix()
    result = await check.async_check()
    assert result.status() == openchecks.Status.Passed
    assert result.items() == [openchecks.Item(0)]


@pytest.mark.asyncio()
async def test_both_check_auto_fix_failed_not_implemented() -> None:
    class MockCheck(openchecks.AsyncBaseCheck, openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        async def async_check(self) -> openchecks.CheckResult[int]:
            return self.check()

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()

    with pytest.raises(NotImplementedError):
        await check.async_auto_fix()
