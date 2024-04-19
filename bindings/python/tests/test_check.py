# ruff: noqa: D103,D100,S101

from __future__ import annotations

from typing import TYPE_CHECKING

import checks
import pytest

if TYPE_CHECKING:  # pragma: no cover
    pass


def test_check_passed_success() -> None:
    class MockCheck(checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == checks.CheckHint.AUTO_FIX | checks.CheckHint.NONE

    result = check.check()
    assert result.status() == checks.Status.Passed
    assert result.message() == "test"


def test_check_failed_success() -> None:
    class MockCheck(checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.failed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == checks.CheckHint.AUTO_FIX | checks.CheckHint.NONE

    result = check.check()
    assert result.status() == checks.Status.Failed
    assert result.message() == "test"


def test_check_auto_fix_success() -> None:
    class MockCheck(checks.BaseCheck):
        def __init__(self) -> None:
            self._value = 1

        def check(self) -> checks.CheckResult[int]:
            if self._value != 0:
                return checks.CheckResult.failed(
                    "failed", [checks.Item(self._value)], can_fix=True
                )

            return checks.CheckResult.passed("passed", [checks.Item(self._value)])

        def auto_fix(self) -> None:
            self._value = 0

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = check.check()
    assert result.status() == checks.Status.Failed
    assert result.items() == [checks.Item(1)]

    check.auto_fix()
    result = check.check()
    assert result.status() == checks.Status.Passed
    assert result.items() == [checks.Item(0)]


@pytest.mark.asyncio()
async def test_check_auto_fix_failed_not_implemented() -> None:
    class MockCheck(checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()

    with pytest.raises(NotImplementedError):
        check.auto_fix()


@pytest.mark.asyncio()
async def test_async_check_passed_success() -> None:
    class MockCheck(checks.AsyncBaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == checks.CheckHint.AUTO_FIX | checks.CheckHint.NONE

    result = await check.async_check()
    assert result.status() == checks.Status.Passed
    assert result.message() == "test"


@pytest.mark.asyncio()
async def test_async_check_failed_success() -> None:
    class MockCheck(checks.AsyncBaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.failed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == checks.CheckHint.AUTO_FIX | checks.CheckHint.NONE

    result = await check.async_check()
    assert result.status() == checks.Status.Failed
    assert result.message() == "test"


@pytest.mark.asyncio()
async def test_async_check_auto_fix_success() -> None:
    class MockCheck(checks.AsyncBaseCheck):
        def __init__(self) -> None:
            self._value = 1

        async def async_check(self) -> checks.CheckResult[int]:
            if self._value != 0:
                return checks.CheckResult.failed(
                    "failed", [checks.Item(self._value)], can_fix=True
                )

            return checks.CheckResult.passed("passed", [checks.Item(self._value)])

        async def async_auto_fix(self) -> None:
            self._value = 0

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await check.async_check()
    assert result.status() == checks.Status.Failed
    assert result.items() == [checks.Item(1)]

    await check.async_auto_fix()
    result = await check.async_check()
    assert result.status() == checks.Status.Passed
    assert result.items() == [checks.Item(0)]


@pytest.mark.asyncio()
async def test_async_check_auto_fix_failed_not_implemented() -> None:
    class MockCheck(checks.AsyncBaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()

    with pytest.raises(NotImplementedError):
        await check.async_auto_fix()


@pytest.mark.asyncio()
async def test_both_check_passed_success() -> None:
    class MockCheck(checks.AsyncBaseCheck, checks.BaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            return self.check()

        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("test")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == checks.CheckHint.AUTO_FIX | checks.CheckHint.NONE

    result = await check.async_check()
    assert result.status() == checks.Status.Passed
    assert result.message() == "test"


@pytest.mark.asyncio()
async def test_both_check_failed_success() -> None:
    class MockCheck(checks.AsyncBaseCheck, checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.failed("test")

        async def async_check(self) -> checks.CheckResult[int]:
            return self.check()

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    assert check.title() == "title"
    assert check.description() == "description"
    assert check.hint() == checks.CheckHint.AUTO_FIX | checks.CheckHint.NONE

    result = await check.async_check()
    assert result.status() == checks.Status.Failed
    assert result.message() == "test"


@pytest.mark.asyncio()
async def test_both_check_auto_fix_success() -> None:
    class MockCheck(checks.AsyncBaseCheck, checks.BaseCheck):
        def __init__(self) -> None:
            self._value = 1

        def check(self) -> checks.CheckResult[int]:
            if self._value != 0:
                return checks.CheckResult.failed(
                    "failed", [checks.Item(self._value)], can_fix=True
                )

            return checks.CheckResult.passed("passed", [checks.Item(self._value)])

        async def async_check(self) -> checks.CheckResult[int]:
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
    assert result.status() == checks.Status.Failed
    assert result.items() == [checks.Item(1)]

    await check.async_auto_fix()
    result = await check.async_check()
    assert result.status() == checks.Status.Passed
    assert result.items() == [checks.Item(0)]


@pytest.mark.asyncio()
async def test_both_check_auto_fix_failed_not_implemented() -> None:
    class MockCheck(checks.AsyncBaseCheck, checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("passed")

        async def async_check(self) -> checks.CheckResult[int]:
            return self.check()

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()

    with pytest.raises(NotImplementedError):
        await check.async_auto_fix()
