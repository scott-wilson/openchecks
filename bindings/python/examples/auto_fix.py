"""This is an example of running a check that can automatically be fixed.

The check requires the same methods as the simple check example, but also
include an ``auto_fix`` method.

The ``auto_fix`` method does not need to do anything other than attempt to fix
the issue, as the ``auto_fix`` function (similar to the ``run`` function) will
automatically run the ``run`` function after attempting the fix and returning
the result. The rule with exceptions in the ``check`` method is the same as the
``auto_fix`` method. If there's an exception raised, then the ``auto_fix``
function will return a ``SystemError`` status.
"""

# ruff: noqa: D101,D102,D103,D107,S101

import openchecks


class IsZeroCheck(openchecks.BaseCheck):
    def __init__(self, number: int) -> None:
        self.__number = number
        super().__init__()

    def title(self) -> str:
        return "Is Zero Check"

    def description(self) -> str:
        return "Check if the number is zero"

    def check(self) -> openchecks.CheckResult:
        if self.__number == 0:
            return openchecks.CheckResult.passed("The number is zero.")
        return openchecks.CheckResult.failed(
            "The number is not zero.",
            [openchecks.Item(self.__number)],
            can_fix=True,
        )

        # Note: The check method must return a CheckResult in all of its
        # branches. If it doesn't, then the system will return a `SystemError`,
        # and that cannot be recovered from unless the check is fixed.

    def auto_fix(self) -> None:
        self.__number = 0


def main() -> None:
    check = IsZeroCheck(1)
    result_fail = openchecks.run(check)

    assert result_fail.status().has_failed()

    result_pass = openchecks.auto_fix(check)

    assert not result_pass.status().has_failed()


if __name__ == "__main__":
    main()
