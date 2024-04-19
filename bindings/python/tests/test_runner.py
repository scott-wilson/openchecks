# ruff: noqa: D103,D100,S101

from __future__ import annotations

import checks
import pytest


def test_run_passed_success() -> None:
    class MockCheck(checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = checks.run(check)

    assert result.status() == checks.Status.Passed
    assert result.message() == "passed"


def test_run_failed_success() -> None:
    class MockCheck(checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.failed("failed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = checks.run(check)

    assert result.status() == checks.Status.Failed
    assert result.message() == "failed"


def test_run_failed_check_returns_not_result() -> None:
    class MockCheck(checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return None  # type: ignore

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = checks.run(check)

    assert result.status() == checks.Status.SystemError


def test_run_failed_check_raises_error() -> None:
    exception = RuntimeError("test")

    class MockCheck(checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = checks.run(check)

    assert result.status() == checks.Status.SystemError
    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, checks.CheckError)
    assert str(err_result) == str("RuntimeError: test")


def test_run_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = checks.run(check)  # type: ignore

    assert result.status() == checks.Status.SystemError


def test_auto_fix_passed_success() -> None:
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
    result = checks.run(check)

    assert result.status() == checks.Status.Failed
    assert result.message() == "failed"

    result = checks.auto_fix(check)
    assert result.status() == checks.Status.Passed
    assert result.message() == "passed"


def test_auto_fix_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = checks.auto_fix(check)  # type: ignore

    assert result.status() == checks.Status.SystemError


def test_auto_fix_failed_check_hint_not_auto_fix() -> None:
    class MockCheck(checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("passed")

        def auto_fix(self) -> None:
            pass

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

        def hint(self) -> checks.CheckHint:
            return checks.CheckHint.NONE

    check = MockCheck()
    result = checks.auto_fix(check)

    assert result.status() == checks.Status.SystemError


def test_auto_fix_failed_auto_fix_raises_error() -> None:
    exception = RuntimeError("Test")

    class MockCheck(checks.BaseCheck):
        def check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("passed")

        def auto_fix(self) -> None:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = checks.auto_fix(check)

    assert result.status() == checks.Status.SystemError

    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, checks.CheckError)
    assert str(err_result) == "RuntimeError: Test"


@pytest.mark.asyncio()
async def test_async_run_passed_success() -> None:
    class MockCheck(checks.AsyncBaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await checks.async_run(check)

    assert result.status() == checks.Status.Passed
    assert result.message() == "passed"


@pytest.mark.asyncio()
async def test_async_run_failed_success() -> None:
    class MockCheck(checks.AsyncBaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.failed("failed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await checks.async_run(check)

    assert result.status() == checks.Status.Failed
    assert result.message() == "failed"


@pytest.mark.asyncio()
async def test_async_run_failed_check_returns_not_result() -> None:
    class MockCheck(checks.AsyncBaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            return None  # type: ignore

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await checks.async_run(check)

    assert result.status() == checks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_run_failed_check_raises_error() -> None:
    exception = RuntimeError("test")

    class MockCheck(checks.AsyncBaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await checks.async_run(check)

    assert result.status() == checks.Status.SystemError
    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, checks.CheckError)
    assert str(err_result) == "RuntimeError: test"


@pytest.mark.asyncio()
async def test_async_run_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = await checks.async_run(check)  # type: ignore

    assert result.status() == checks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_auto_fix_passed_success() -> None:
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
    result = await checks.async_run(check)

    assert result.status() == checks.Status.Failed
    assert result.message() == "failed"

    result = await checks.async_auto_fix(check)
    assert result.status() == checks.Status.Passed
    assert result.message() == "passed"


@pytest.mark.asyncio()
async def test_async_auto_fix_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = await checks.async_auto_fix(check)  # type: ignore

    assert result.status() == checks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_auto_fix_failed_check_hint_not_auto_fix() -> None:
    class MockCheck(checks.AsyncBaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("passed")

        async def async_auto_fix(self) -> None:
            pass

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

        def hint(self) -> checks.CheckHint:
            return checks.CheckHint.NONE

    check = MockCheck()
    result = await checks.async_auto_fix(check)

    assert result.status() == checks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_auto_fix_failed_auto_fix_raises_error() -> None:
    exception = RuntimeError("Test")

    class MockCheck(checks.AsyncBaseCheck):
        async def async_check(self) -> checks.CheckResult[int]:
            return checks.CheckResult.passed("passed")

        async def async_auto_fix(self) -> None:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await checks.async_auto_fix(check)

    assert result.status() == checks.Status.SystemError

    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, checks.CheckError)
    assert str(err_result) == "RuntimeError: Test"
