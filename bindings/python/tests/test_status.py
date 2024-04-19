# ruff: noqa: D103,D100,S101

from __future__ import annotations

import checks
import pytest


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (checks.Status.Pending, True),
        (checks.Status.Skipped, False),
        (checks.Status.Passed, False),
        (checks.Status.Warning, False),
        (checks.Status.Failed, False),
        (checks.Status.SystemError, False),
    ],
)
def test_status_is_pending_success(status: checks.Status, expected: bool) -> None:
    assert status.is_pending() == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (checks.Status.Pending, False),
        (checks.Status.Skipped, False),
        (checks.Status.Passed, True),
        (checks.Status.Warning, True),
        (checks.Status.Failed, False),
        (checks.Status.SystemError, False),
    ],
)
def test_status_has_passed_success(status: checks.Status, expected: bool) -> None:
    assert status.has_passed() == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (checks.Status.Pending, False),
        (checks.Status.Skipped, False),
        (checks.Status.Passed, False),
        (checks.Status.Warning, False),
        (checks.Status.Failed, True),
        (checks.Status.SystemError, True),
    ],
)
def test_status_has_failed_success(status: checks.Status, expected: bool) -> None:
    assert status.has_failed() == expected
