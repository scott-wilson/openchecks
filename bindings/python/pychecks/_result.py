from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:  # pragma: no cover
    from types import TracebackType
    from typing import List, Optional, Tuple

    from . import Item, Status

T = TypeVar("T")

__all__ = [
    "CheckResult",
]


class CheckResult(Generic[T]):
    """A check result contains all of the information needed to know the
    status of a check.

    It contains useful information such as...

    - Status: A machine readable value that can be used to quickly tell whether
    the test passed, failed, or is pending.
    - Message: A human readable description of the status. If the status failed,
    this should contain information on what happened, and how to fix the
    issue.
    - Items: An iterable of items that caused the result. For example, if a
    check that validates if objects are named correctly failed, then the items
    would include the offending objects.
    - Can fix: Whether the check can be fixed or not. For example, if a check
    requires textures to be no larger than a certain size, includes a method
    to resize the textures, and failed, the result could be marked as fixable
    so the user could press an "auto-fix" button in a user interface to resize
    the textures.
    - Can skip: Usually, a validation system should not let any checks that
    failed to go forward with, for example, publishing an asset. Sometimes a
    studio might decide that the error isn't critical enough to always fail if
    a supervisor approves the fail to pass through.
    - Error: If the status is Status.SystemError, then it may also contain the
    error that caused the result. Other statuses shouldn't contain an error.
    - Check duration: A diagnostic tool that could be exposed in a user
    interface to let the user know how long it took to run the check.
    - Fix duration: A diagnostic tool that could be exposed in a user
    interface to let the user know how long it took to run the auto-fix.

    It is suggested to use one of the other constructor methods such as
    :code:`CheckResult.passed` for convenience.

    Args:
        status: The status for the check.
        message: The human readable description of the status.
        items: The items that caused the result.
        can_fix: Whether the check can be fixed or not.
        can_skip: Whether the check can be skipped or not.
        error: The error for the status.
    """

    def __init__(
        self,
        status: Status,
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
        error: Optional[Tuple[BaseException, Optional[TracebackType]]] = None,
    ) -> None:
        self.__status = status
        self.__message = message
        self.__items = items
        self.__can_fix = can_fix
        self.__can_skip = can_skip
        self.__error = error
        self._check_duration: datetime.timedelta = datetime.timedelta()
        self._fix_duration: datetime.timedelta = datetime.timedelta()

    def status(self) -> Status:
        """The status of the result.

        Returns:
            Status: The result status.
        """
        return self.__status

    def message(self) -> str:
        """A human readable message for the result.

        If a check has issues, then this should include information about what
        happened and how to fix the issue.

        Returns:
            str: The result message.
        """
        return self.__message

    def items(self) -> Optional[List[Item[T]]]:
        """The items that caused the result.

        Returns:
            The items that caused the result.
        """
        return self.__items

    def can_fix(self) -> bool:
        """Whether the result can be fixed or not.

        If the status is :code:`Status.SystemError`, then the check can
        **never** be fixed without fixing the issue with the validation system.

        Returns:
            Whether the check can be fixed or not.
        """
        from . import Status

        if self.__status == Status.SystemError:
            return False

        return self.__can_fix

    def can_skip(self) -> bool:
        """Whether the result can be skipped or not.

        A result should only be skipped if the studio decides that letting the
        failed check pass will not cause serious issues to the next department.
        Also, it is recommended that check results are not skipped unless a
        supervisor overrides the skip.

        If the status is :code:`Status.SystemError`, then the check can
        **never** be skipped without fixing the issue with the validation
        system.

        Returns:
            Whether the check can be skipped or not.
        """
        from . import Status

        if self.__status == Status.SystemError:
            return False

        return self.__can_skip

    def error(self) -> Optional[Tuple[BaseException, Optional[TracebackType]]]:
        """The error that caused the result.

        This only really applies to the
        :code:`Status.SystemError` status. Other results should not include the
        error object.

        Returns:
            The error for the status.
        """
        return self.__error

    def check_duration(self) -> datetime.timedelta:
        """The duration of a check.

        This is not settable outside of the check runner. It can be exposed to
        a user to let them know how long a check took to run, or be used as a
        diagnostics tool to improve check performance.

        Returns:
            The check duration.
        """
        return self._check_duration

    def fix_duration(self) -> datetime.timedelta:
        """The duration of an auto-fix.

        This is not settable outside of the auto-fix runner. It can be exposed
        to a user to let them know how long an auto-fix took to run, or be used
        as a diagnostics tool to improve check performance.

        Returns:
            The auto-fix duration.
        """
        return self._fix_duration

    @classmethod
    def passed(
        cls,
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
    ) -> CheckResult[T]:
        """Create a new result that passed a check.

        Args:
            message: The human readable description of the status.
            items: The items that caused the result.
            can_fix: Whether the check can be fixed or not.
            can_skip: Whether the check can be skipped or not.

        Returns:
            The passed result.
        """
        from . import Status

        return cls(Status.Passed, message, items, can_fix, can_skip)

    @classmethod
    def skipped(
        cls,
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
    ) -> CheckResult[T]:
        """Create a new result that skipped a check.

        Args:
            message: The human readable description of the status.
            items: The items that caused the result.
            can_fix: Whether the check can be fixed or not.
            can_skip: Whether the check can be skipped or not.

        Returns:
            The skipped result.
        """
        from . import Status

        return cls(Status.Skipped, message, items, can_fix, can_skip)

    @classmethod
    def warning(
        cls,
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
    ) -> CheckResult[T]:
        """Create a new result that passed the check with a warning.

        Warnings should be considered as passes, but with notes saying that
        there *may* be an issue. For example, textures could be any resolution,
        but anything over 4096x4096 could be marked as a potential performance
        issue.

        Args:
            message: The human readable description of the status.
            items: The items that caused the result.
            can_fix: Whether the check can be fixed or not.
            can_skip: Whether the check can be skipped or not.

        Returns:
            The passed with warning result.
        """
        from . import Status

        return cls(Status.Warning, message, items, can_fix, can_skip)

    @classmethod
    def failed(
        cls,
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
    ) -> CheckResult[T]:
        """Create a new result that failed a check.

        Failed checks in a validation system should not let the following
        process continue forward unless the check can be skipped/overridden by
        a supervisor, or is fixed and later passes, or passes with a warning.

        Args:
            message: The human readable description of the status.
            items: The items that caused the result.
            can_fix: Whether the check can be fixed or not.
            can_skip: Whether the check can be skipped or not.

        Returns:
            The failed result.
        """
        from . import Status

        return cls(Status.Failed, message, items, can_fix, can_skip)
