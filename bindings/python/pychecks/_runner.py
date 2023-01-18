from __future__ import annotations

import datetime
import sys
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:  # pragma: no cover
    from . import AsyncBaseCheck, BaseCheck, CheckResult

T = TypeVar("T")

__all__ = [
    "run",
    "auto_fix",
    "async_run",
    "async_auto_fix",
]


def run(check: BaseCheck[T]) -> CheckResult[T]:
    """Run a check.

    Args:
        check: The check to run.

    Returns:
        The result of the check.
    """
    from . import BaseCheck, CheckResult, Status

    if not isinstance(check, BaseCheck):
        return CheckResult(Status.SystemError, f"{check} does not inherit BaseCheck")

    start_time = datetime.datetime.now()

    try:
        result = check.check()
    except Exception as err:
        _, _, tb = sys.exc_info()
        result = CheckResult(
            Status.SystemError,
            "An error occurred while running the check",
            error=(err, tb),
        )
    if not isinstance(result, CheckResult):
        result = CheckResult(Status.SystemError, f"{result} is not a CheckResult")

    duration = datetime.datetime.now() - start_time
    result._check_duration = duration

    return result


def auto_fix(check: BaseCheck[T]) -> CheckResult[T]:
    """Automatically fix an issue found by a check.

    This function should only be run after the check runner
    returns a result, and that result can be fixed. Otherwise, the fix might try
    to fix an already "good" object, causing issues with the object.

    The auto-fix will re-run the check runner to validate that it
    has actually fixed the issue.

    This will return a result with the Status.SystemError status if the check
    does not have the CheckHint.AUTO_FIX flag set, or an auto-fix returned an
    error. In the case of the latter, it will include the error with the check
    result.

    Args:
        check: The check to fix.

    Returns:
        The result of the fixed check.
    """
    from . import BaseCheck, CheckHint, CheckResult, Status

    if not isinstance(check, BaseCheck):
        return CheckResult(Status.SystemError, f"{check} does not inherit BaseCheck")

    if CheckHint.AUTO_FIX not in check.hint():
        return CheckResult(Status.SystemError, f"{check} does not support auto fixes")

    start_time = datetime.datetime.now()

    try:
        check.auto_fix()
        result = run(check)
    except Exception as err:
        _, _, tb = sys.exc_info()
        result = CheckResult(
            Status.SystemError,
            "An error occurred while running the check",
            error=(err, tb),
        )

    duration = datetime.datetime.now() - start_time
    result._fix_duration = duration

    return result


async def async_run(check: AsyncBaseCheck[T]) -> CheckResult[T]:
    """Run a check.

    Args:
        check: The check to run.

    Returns:
        The result of the check.
    """
    from . import AsyncBaseCheck, CheckResult, Status

    if not isinstance(check, AsyncBaseCheck):
        return CheckResult(
            Status.SystemError, f"{check} does not inherit AsyncBaseCheck"
        )

    start_time = datetime.datetime.now()

    try:
        result = await check.async_check()
    except Exception as err:
        _, _, tb = sys.exc_info()
        result = CheckResult(
            Status.SystemError,
            "An error occurred while running the check",
            error=(err, tb),
        )
    if not isinstance(result, CheckResult):
        result = CheckResult(Status.SystemError, f"{result} is not a CheckResult")

    duration = datetime.datetime.now() - start_time
    result._check_duration = duration

    return result


async def async_auto_fix(check: AsyncBaseCheck[T]) -> CheckResult[T]:
    """Automatically fix an issue found by a check.

    This function should only be run after the check runner
    returns a result, and that result can be fixed. Otherwise, the fix might
    try to fix an already "good" object, causing issues with the object.

    The auto-fix will re-run the check runner to validate that it
    has actually fixed the issue.

    This will return a result with the Status.SystemError status if the check
    does not have the CheckHint.AUTO_FIX flag set, or an auto-fix returned an
    error. In the case of the latter, it will include the error with the check
    result.

    Args:
        check: The check to fix.

    Returns:
        The result of the fixed check.
    """
    from . import AsyncBaseCheck, CheckHint, CheckResult, Status

    if not isinstance(check, AsyncBaseCheck):
        return CheckResult(Status.SystemError, f"{check} does not inherit BaseCheck")

    if CheckHint.AUTO_FIX not in check.hint():
        return CheckResult(Status.SystemError, f"{check} does not support auto fixes")

    start_time = datetime.datetime.now()

    try:
        await check.async_auto_fix()
        result = await async_run(check)
    except Exception as err:
        _, _, tb = sys.exc_info()
        result = CheckResult(
            Status.SystemError,
            "An error occurred while running the check",
            error=(err, tb),
        )

    duration = datetime.datetime.now() - start_time
    result._fix_duration = duration

    return result
