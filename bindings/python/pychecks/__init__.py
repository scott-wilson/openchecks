from __future__ import annotations

import time
from typing import TYPE_CHECKING, TypeVar
from pychecks.pychecks import (
    BaseCheck,
    CheckHint,
    CheckResult,
    Item,
    Status,
)

if TYPE_CHECKING:  # pragma: no cover
    pass


__all__ = [
    "BaseCheck",
    "CheckHint",
    "CheckResult",
    "Item",
    "Status",
    "auto_fix",
    "run",
]

T = TypeVar("T")


def run(check: BaseCheck[T]) -> CheckResult[T]:
    """Run a check.

    Args:
        check: The check to run.

    Returns:
        The result of the check.
    """
    if not isinstance(check, BaseCheck):
        return CheckResult(Status.SystemError, f"{check} does not inherit BaseCheck")

    start_time = time.time()

    try:
        result = check.check()
    except Exception as err:
        result = CheckResult(
            Status.SystemError, "An error occurred while running the check", error=err
        )
    if not isinstance(result, CheckResult):
        result = CheckResult(Status.SystemError, f"{result} is not a CheckResult")

    duration = time.time() - start_time
    result._set_check_duration(duration)

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
    if not isinstance(check, BaseCheck):
        return CheckResult(Status.SystemError, f"{check} does not inherit BaseCheck")

    if CheckHint.AUTO_FIX not in check.hint():
        return CheckResult(Status.SystemError, f"{check} does not support auto fixes")

    start_time = time.time()

    try:
        check.auto_fix()
        result = run(check)
    except Exception as err:
        result = CheckResult(
            Status.SystemError, "An error occurred while running the check", error=err
        )

    duration = time.time() - start_time
    result._set_fix_duration(duration)

    return result
