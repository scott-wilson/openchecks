from __future__ import annotations

import openchecks


def test_run_passed_success() -> None:
    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return openchecks.CheckResult.passed("passed")

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    scheduler = openchecks.Scheduler()
    results = scheduler.run([check])

    assert len(results) == 1

    for result_check, result in results:
        assert isinstance(result_check, openchecks.BaseCheck)
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check
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
    scheduler = openchecks.Scheduler()
    results = scheduler.run([check])

    assert len(results) == 1

    for result_check, result in results:
        assert isinstance(result_check, openchecks.BaseCheck)
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check
        assert result.status() == openchecks.Status.Failed
        assert result.message() == "failed"


def test_run_failed_check_returns_not_result() -> None:
    class MockCheck(openchecks.BaseCheck):
        def check(self) -> openchecks.CheckResult[int]:
            return None  # type: ignore  # noqa: PGH003

        def title(self) -> str:
            return "title"

        def description(self) -> str:
            return "description"

    check = MockCheck()
    scheduler = openchecks.Scheduler()
    results = scheduler.run([check])

    assert len(results) == 1

    for result_check, result in results:
        assert isinstance(result_check, openchecks.BaseCheck)
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check
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
    scheduler = openchecks.Scheduler()
    results = scheduler.run([check])

    assert len(results) == 1

    for result_check, result in results:
        assert isinstance(result_check, openchecks.BaseCheck)
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check
        assert result.status() == openchecks.Status.SystemError
        err_result = result.error()
        assert err_result is not None
        assert isinstance(err_result, openchecks.CheckError)
        assert str(err_result) == "RuntimeError: test"


def test_run_failed_check_does_not_inherit_base_check() -> None:
    check = None
    scheduler = openchecks.Scheduler()
    results = scheduler.run([check])  # type: ignore  # noqa: PGH003

    assert len(results) == 1

    for result_check, result in results:
        assert result_check is None
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check
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
    scheduler = openchecks.Scheduler()
    results = scheduler.run([check])

    assert len(results) == 1

    for result_check, result in results:
        assert isinstance(result_check, openchecks.BaseCheck)
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check
        assert result.status() == openchecks.Status.Failed
        assert result.message() == "failed"

    scheduler = openchecks.Scheduler()
    results = scheduler.auto_fix([check])

    assert len(results) == 1

    for result_check, result in results:
        assert isinstance(result_check, openchecks.BaseCheck)
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check
        assert result.status() == openchecks.Status.Passed
        assert result.message() == "passed"


def test_auto_fix_failed_check_does_not_inherit_base_check() -> None:
    check = None
    scheduler = openchecks.Scheduler()
    results = scheduler.run([check])  # type: ignore  # noqa: PGH003

    assert len(results) == 1

    for result_check, result in results:
        assert result_check is None
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check
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
    scheduler = openchecks.Scheduler()
    results = scheduler.auto_fix([check])

    assert len(results) == 1

    for result_check, result in results:
        assert isinstance(result_check, openchecks.BaseCheck)
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check
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
    scheduler = openchecks.Scheduler()
    results = scheduler.auto_fix([check])

    assert len(results) == 1

    for result_check, result in results:
        assert isinstance(result_check, openchecks.BaseCheck)
        assert isinstance(result, openchecks.CheckResult)
        assert check == result_check

        assert result.status() == openchecks.Status.SystemError

        err_result = result.error()
        assert err_result is not None
        assert isinstance(err_result, openchecks.CheckError)
        assert str(err_result) == "RuntimeError: Test"
