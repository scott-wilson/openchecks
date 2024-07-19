# ruff: noqa: D103,D100,S101

from __future__ import annotations

import openchecks
import pytest


def test_run_passed_success() -> None:
    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = openchecks.run(check)

    assert result.status() == openchecks.Status.Passed
    assert result.message() == "passed"


def test_run_failed_success() -> None:
    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.failed("failed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = openchecks.run(check)

    assert result.status() == openchecks.Status.Failed
    assert result.message() == "failed"


def test_run_failed_check_returns_not_result() -> None:
    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return None  # type: ignore

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = openchecks.run(check)

    assert result.status() == openchecks.Status.SystemError


def test_run_failed_check_raises_error() -> None:
    exception = RuntimeError("test")

    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = openchecks.run(check)

    assert result.status() == openchecks.Status.SystemError
    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, openchecks.CheckError)
    assert str(err_result) == str("RuntimeError: test")


def test_run_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = openchecks.run(check)  # type: ignore

    assert result.status() == openchecks.Status.SystemError


def test_auto_fix_passed_success() -> None:
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
    result = openchecks.run(check)

    assert result.status() == openchecks.Status.Failed
    assert result.message() == "failed"

    result = openchecks.auto_fix(check)
    assert result.status() == openchecks.Status.Passed
    assert result.message() == "passed"


def test_auto_fix_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = openchecks.auto_fix(check)  # type: ignore

    assert result.status() == openchecks.Status.SystemError


def test_auto_fix_failed_check_hint_not_auto_fix() -> None:
    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        def auto_fix(self) -> None:
            pass

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

        def hint(self) -> openchecks.CheckHint:
            return openchecks.CheckHint.NONE

    check = MockCheck()
    result = openchecks.auto_fix(check)

    assert result.status() == openchecks.Status.SystemError


def test_auto_fix_failed_auto_fix_raises_error() -> None:
    exception = RuntimeError("Test")

    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        def auto_fix(self) -> None:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = openchecks.auto_fix(check)

    assert result.status() == openchecks.Status.SystemError

    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, openchecks.CheckError)
    assert str(err_result) == "RuntimeError: Test"


@pytest.mark.asyncio()
async def test_async_run_passed_success() -> None:
    class MockCheck(openchecks.AsyncBaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await openchecks.async_run(check)

    assert result.status() == openchecks.Status.Passed
    assert result.message() == "passed"


@pytest.mark.asyncio()
async def test_async_run_failed_success() -> None:
    class MockCheck(openchecks.AsyncBaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.failed("failed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await openchecks.async_run(check)

    assert result.status() == openchecks.Status.Failed
    assert result.message() == "failed"


@pytest.mark.asyncio()
async def test_async_run_failed_check_returns_not_result() -> None:
    class MockCheck(openchecks.AsyncBaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            return None  # type: ignore

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await openchecks.async_run(check)

    assert result.status() == openchecks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_run_failed_check_raises_error() -> None:
    exception = RuntimeError("test")

    class MockCheck(openchecks.AsyncBaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await openchecks.async_run(check)

    assert result.status() == openchecks.Status.SystemError
    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, openchecks.CheckError)
    assert str(err_result) == "RuntimeError: test"


@pytest.mark.asyncio()
async def test_async_run_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = await openchecks.async_run(check)  # type: ignore

    assert result.status() == openchecks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_auto_fix_passed_success() -> None:
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
    result = await openchecks.async_run(check)

    assert result.status() == openchecks.Status.Failed
    assert result.message() == "failed"

    result = await openchecks.async_auto_fix(check)
    assert result.status() == openchecks.Status.Passed
    assert result.message() == "passed"


@pytest.mark.asyncio()
async def test_async_auto_fix_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = await openchecks.async_auto_fix(check)  # type: ignore

    assert result.status() == openchecks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_auto_fix_failed_check_hint_not_auto_fix() -> None:
    class MockCheck(openchecks.AsyncBaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        async def async_auto_fix(self) -> None:
            pass

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

        def hint(self) -> openchecks.CheckHint:
            return openchecks.CheckHint.NONE

    check = MockCheck()
    result = await openchecks.async_auto_fix(check)

    assert result.status() == openchecks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_auto_fix_failed_auto_fix_raises_error() -> None:
    exception = RuntimeError("Test")

    class MockCheck(openchecks.AsyncBaseCheck):
        async def async_check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        async def async_auto_fix(self) -> None:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await openchecks.async_auto_fix(check)

    assert result.status() == openchecks.Status.SystemError

    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, openchecks.CheckError)
    assert str(err_result) == "RuntimeError: Test"
