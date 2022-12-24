from __future__ import annotations

from typing import TYPE_CHECKING
import pytest
import pychecks

if TYPE_CHECKING:
    pass


@pytest.mark.parametrize(
    "status, expected",
    [
        (pychecks.Status.Pending, True),
        (pychecks.Status.Skipped, False),
        (pychecks.Status.Passed, False),
        (pychecks.Status.Warning, False),
        (pychecks.Status.Failed, False),
        (pychecks.Status.SystemError, False),
    ],
)
def test_status_is_pending_success(status: pychecks.Status, expected: bool):
    assert status.is_pending() == expected


@pytest.mark.parametrize(
    "status, expected",
    [
        (pychecks.Status.Pending, False),
        (pychecks.Status.Skipped, True),
        (pychecks.Status.Passed, True),
        (pychecks.Status.Warning, True),
        (pychecks.Status.Failed, False),
        (pychecks.Status.SystemError, False),
    ],
)
def test_status_has_passed_success(status: pychecks.Status, expected: bool):
    assert status.has_passed() == expected


@pytest.mark.parametrize(
    "status, expected",
    [
        (pychecks.Status.Pending, False),
        (pychecks.Status.Skipped, False),
        (pychecks.Status.Passed, False),
        (pychecks.Status.Warning, False),
        (pychecks.Status.Failed, True),
        (pychecks.Status.SystemError, True),
    ],
)
def test_status_has_failed_success(status: pychecks.Status, expected: bool):
    assert status.has_failed() == expected
