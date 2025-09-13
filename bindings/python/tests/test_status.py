from __future__ import annotations

import pytest

import openchecks


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (openchecks.Status.Pending, True),
        (openchecks.Status.Skipped, False),
        (openchecks.Status.Passed, False),
        (openchecks.Status.Warning, False),
        (openchecks.Status.Failed, False),
        (openchecks.Status.SystemError, False),
    ],
)
def test_status_is_pending_success(status: openchecks.Status, expected: bool) -> None:  # noqa: FBT001
    assert status.is_pending() == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (openchecks.Status.Pending, False),
        (openchecks.Status.Skipped, False),
        (openchecks.Status.Passed, True),
        (openchecks.Status.Warning, True),
        (openchecks.Status.Failed, False),
        (openchecks.Status.SystemError, False),
    ],
)
def test_status_has_passed_success(status: openchecks.Status, expected: bool) -> None:  # noqa: FBT001
    assert status.has_passed() == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (openchecks.Status.Pending, False),
        (openchecks.Status.Skipped, False),
        (openchecks.Status.Passed, False),
        (openchecks.Status.Warning, False),
        (openchecks.Status.Failed, True),
        (openchecks.Status.SystemError, True),
    ],
)
def test_status_has_failed_success(status: openchecks.Status, expected: bool) -> None:  # noqa: FBT001
    assert status.has_failed() == expected
