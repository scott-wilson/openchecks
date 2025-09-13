"""This is an example of running a simple check.

This check cannot be automatically fixed, and is not async. The only methods
that are required are the ``title`` (the human readable title of the check),
``description`` (human readable description of the check), and ``check``
(the method that validates the input).

The checks are similar in concept to unit tests with Python's ``unittest``
module or ``pytest``. Except that the check method should not raise an error.
In fact, raising an error or having the check method return anything but a
check result will result in a special status called ``SystemError``, which
ignores ``CheckResult.can_skip()`` and always returns ``False``. In other
words, ``SystemError`` is a status that must be fixed by the developers
implementing or supporting the checks.
"""

# ruff: noqa: D101,D102,D103,D107,S101

import openchecks


class IsEvenCheck(openchecks.BaseCheck):
    def __init__(self, number: int) -> None:
        self.__number = number
        super().__init__()

    def title(self) -> str:
        return "Is Even Check"

    def description(self) -> str:
        return "Check if the number is even"

    def check(self) -> openchecks.CheckResult:
        if self.__number % 2 == 0:
            return openchecks.CheckResult.passed("The number is even.")
        return openchecks.CheckResult.failed(
            "The number is not even.", [openchecks.Item(self.__number)]
        )

        # Note: The check method must return a CheckResult in all of its
        # branches. If it doesn't, then the system will return a `SystemError`,
        # and that cannot be recovered from unless the check is fixed.


def main() -> None:
    check_pass = IsEvenCheck(2)
    result_pass = openchecks.run(check_pass)

    assert not result_pass.status().has_failed()

    check_fail = IsEvenCheck(1)
    result_fail = openchecks.run(check_fail)

    assert result_fail.status().has_failed()


if __name__ == "__main__":
    main()
