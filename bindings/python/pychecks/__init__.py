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
