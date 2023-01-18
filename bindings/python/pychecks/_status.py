import enum

__all__ = [
    "Status",
]


class Status(enum.Enum):
    """The status enum represents a result status.

    - Pending: The check is waiting to run. A check should not return this
      status, but instead this can be used by a user interface to let a user
      know that the check is ready to run.
    - Skipped: The check has been skipped. A check might return this to let the
      user know that an element it depends on is invalid (such as a file
      doesn't) exist, or a check scheduler may make child checks return this
      status if a check fails.
    - Passed: The check has successfully passed without issue.
    - Warning: There were issues found, but they are not deemed failures. This
      can be treated the same as a pass.
    - Failed: The check found an issue that caused it to fail. A validation
      system should block the process following the validations to have the
      issue fixed, unless the result allows skipping the check.
    - SystemError: There was an issue with a check or runner itself. For
      example, code that the check depends on has an error, or the check is
      otherwise invalid. If a validation process finds a result with this
      status, then the process should not let the next process after run at all
      until the check has been fixed by a developer.
    """

    Pending = enum.auto()
    """
    The check is waiting to run. A check should not return this status, but
    instead this can be used by a user interface to let a user know that the
    check is ready to run.
    """
    Skipped = enum.auto()
    """
    The check has been skipped. A check might return this to let the user know
    that an element it depends on is invalid (such as a file doesn't) exist, or
    a check scheduler may make child checks return this status if a check
    fails.
    """
    Passed = enum.auto()
    """The check has successfully passed without issue."""
    Warning = enum.auto()
    """
    There were issues found, but they are not deemed failures. This can be
    treated the same as a pass.
    """
    Failed = enum.auto()
    """
    The check found an issue that caused it to fail. A validation system should
    block the process following the validations to have the issue fixed, unless
    the result allows skipping the check.
    """
    SystemError = enum.auto()
    """
    There was an issue with a check or runner itself. For example, code that
    the check depends on has an error, or the check is otherwise invalid. If a
    validation process finds a result with this status, then the process should
    not let the next process after run at all until the check has been fixed by
    a developer.
    """

    def is_pending(self) -> bool:
        """Return if a check is waiting to be run.

        Returns:
            bool: Whether the check is waiting to run.
        """
        return self == Status.Pending

    def has_passed(self) -> bool:
        """Return if a check has passed.

        Returns:
            bool: Whether the check has passed or not.
        """
        return self in (Status.Skipped, Status.Passed, Status.Warning)

    def has_failed(self) -> bool:
        """Return if a check has failed.

        Returns:
            bool: Whether the check has failed or not.
        """
        return self in (Status.Failed, Status.SystemError)
