from __future__ import annotations

import abc
import enum
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:  # pragma: no cover
    from . import CheckResult

T = TypeVar("T")

__all__ = [
    "AsyncBaseCheck",
    "BaseCheck",
    "CheckHint",
    "CheckMetadata",
]


class CheckHint(enum.Flag):
    """The check hint flags contains useful information such as whether the
    check should support auto-fixing issues.
    """

    NONE = 0b0
    """The check supports no extra features. This should be considered the most
    conservative check *feature*. For example, no auto-fix, check cannot be
    skipped before running, etc.
    """

    AUTO_FIX = enum.auto()
    """The check supports auto-fixing. This does not guarantee that the
    auto-fix is implemented, but instead that the auto-fix should be
    implemented.
    """


class CheckMetadata(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def title(self) -> str:
        """The human readable title for the check.

        User interfaces should use the title for displaying the check.

        Returns:
            The title for the check.
        """
        ...  # pragma: no cover

    @abc.abstractmethod
    def description(self) -> str:
        """The human readable description for the check.

        This should include information about what the check is looking for,
        what are the conditions for the different statuses it supports, and if
        there's an auto-fix, what the auto-fix will do.

        Returns:
            The description for the check.
        """
        ...  # pragma: no cover

    def hint(self) -> CheckHint:
        """The hint gives information about what features the check supports.

        Returns:
            The hint for the check.
        """
        return CheckHint.AUTO_FIX | CheckHint.NONE


class BaseCheck(Generic[T], CheckMetadata, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def check(self) -> CheckResult[T]:
        """Run a validation on the input data and output the result of the
        validation.

        Returns:
            The result of the check.
        """
        ...  # pragma: no cover

    def auto_fix(self) -> None:
        """Automatically fix the issue detected by the :code:`BaseCheck.check`
        method.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__}.auto_fix is not implemented"
        )


class AsyncBaseCheck(Generic[T], CheckMetadata, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def async_check(self) -> CheckResult[T]:
        """Run a validation on the input data and output the result of the
        validation.

        Returns:
            The result of the check.
        """
        ...  # pragma: no cover

    async def async_auto_fix(self) -> None:
        """Automatically fix the issue detected by the
        :code:`AsyncBaseCheck.async_check` method.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__}.async_auto_fix is not implemented"
        )
