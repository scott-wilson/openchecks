# ruff: noqa: D103,D100,S101

from __future__ import annotations

import pychecks
import pytest


def test_run_passed_success() -> None:
    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = pychecks.run(check)

    assert result.status() == pychecks.Status.Passed
    assert result.message() == "passed"


def test_run_failed_success() -> None:
    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.failed("failed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = pychecks.run(check)

    assert result.status() == pychecks.Status.Failed
    assert result.message() == "failed"


def test_run_failed_check_returns_not_result() -> None:
    class MockCheck(pychecks.BaseCheck):
        def check(self) -> pychecks.CheckResult[int]:
            return None  # type: ignore

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = pychecks.run(check)

    assert result.status() == pychecks.Status.SystemError


def test_run_failed_check_raises_error() -> None:
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
    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, pychecks.CheckError)
    assert str(err_result) == str("RuntimeError: test")


def test_run_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = pychecks.run(check)  # type: ignore

    assert result.status() == pychecks.Status.SystemError


def test_auto_fix_passed_success() -> None:
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
    result = pychecks.run(check)

    assert result.status() == pychecks.Status.Failed
    assert result.message() == "failed"

    result = pychecks.auto_fix(check)
    assert result.status() == pychecks.Status.Passed
    assert result.message() == "passed"


def test_auto_fix_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = pychecks.auto_fix(check)  # type: ignore

    assert result.status() == pychecks.Status.SystemError


def test_auto_fix_failed_check_hint_not_auto_fix() -> None:
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


def test_auto_fix_failed_auto_fix_raises_error() -> None:
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

    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, pychecks.CheckError)
    assert str(err_result) == "RuntimeError: Test"


@pytest.mark.asyncio()
async def test_async_run_passed_success() -> None:
    class MockCheck(pychecks.AsyncBaseCheck):
        async def async_check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await pychecks.async_run(check)

    assert result.status() == pychecks.Status.Passed
    assert result.message() == "passed"


@pytest.mark.asyncio()
async def test_async_run_failed_success() -> None:
    class MockCheck(pychecks.AsyncBaseCheck):
        async def async_check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.failed("failed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await pychecks.async_run(check)

    assert result.status() == pychecks.Status.Failed
    assert result.message() == "failed"


@pytest.mark.asyncio()
async def test_async_run_failed_check_returns_not_result() -> None:
    class MockCheck(pychecks.AsyncBaseCheck):
        async def async_check(self) -> pychecks.CheckResult[int]:
            return None  # type: ignore

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await pychecks.async_run(check)

    assert result.status() == pychecks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_run_failed_check_raises_error() -> None:
    exception = RuntimeError("test")

    class MockCheck(pychecks.AsyncBaseCheck):
        async def async_check(self) -> pychecks.CheckResult[int]:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await pychecks.async_run(check)

    assert result.status() == pychecks.Status.SystemError
    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, pychecks.CheckError)
    assert str(err_result) == "RuntimeError: test"


@pytest.mark.asyncio()
async def test_async_run_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = await pychecks.async_run(check)  # type: ignore

    assert result.status() == pychecks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_auto_fix_passed_success() -> None:
    class MockCheck(pychecks.AsyncBaseCheck):
        def __init__(self) -> None:
            self._value = 1

        async def async_check(self) -> pychecks.CheckResult[int]:
            if self._value != 0:
                return pychecks.CheckResult.failed(
                    "failed", [pychecks.Item(self._value)], can_fix=True
                )

            return pychecks.CheckResult.passed("passed", [pychecks.Item(self._value)])

        async def async_auto_fix(self) -> None:
            self._value = 0

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await pychecks.async_run(check)

    assert result.status() == pychecks.Status.Failed
    assert result.message() == "failed"

    result = await pychecks.async_auto_fix(check)
    assert result.status() == pychecks.Status.Passed
    assert result.message() == "passed"


@pytest.mark.asyncio()
async def test_async_auto_fix_failed_check_does_not_inherit_base_check() -> None:
    check = None
    result = await pychecks.async_auto_fix(check)  # type: ignore

    assert result.status() == pychecks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_auto_fix_failed_check_hint_not_auto_fix() -> None:
    class MockCheck(pychecks.AsyncBaseCheck):
        async def async_check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.passed("passed")

        async def async_auto_fix(self) -> None:
            pass

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

        def hint(self) -> pychecks.CheckHint:
            return pychecks.CheckHint.NONE

    check = MockCheck()
    result = await pychecks.async_auto_fix(check)

    assert result.status() == pychecks.Status.SystemError


@pytest.mark.asyncio()
async def test_async_auto_fix_failed_auto_fix_raises_error() -> None:
    exception = RuntimeError("Test")

    class MockCheck(pychecks.AsyncBaseCheck):
        async def async_check(self) -> pychecks.CheckResult[int]:
            return pychecks.CheckResult.passed("passed")

        async def async_auto_fix(self) -> None:
            raise exception

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    result = await pychecks.async_auto_fix(check)

    assert result.status() == pychecks.Status.SystemError

    err_result = result.error()
    assert err_result is not None
    assert isinstance(err_result, pychecks.CheckError)
    assert str(err_result) == "RuntimeError: Test"
