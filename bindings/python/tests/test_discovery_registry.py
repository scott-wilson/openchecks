from __future__ import annotations

import pytest

import openchecks


class Check(openchecks.BaseCheck):
    def check(self) -> openchecks.CheckResult[int]:
        return openchecks.CheckResult.passed("test")

    def title(self) -> str:
        return "title"

    def description(self) -> str:
        return "description"


class AsyncCheck(openchecks.AsyncBaseCheck):
    async def async_check(self) -> openchecks.CheckResult[int]:
        return openchecks.CheckResult.passed("test")

    def title(self) -> str:
        return "title"

    def description(self) -> str:
        return "description"


def test_discovery_registry_register_and_gather_success() -> None:
    registry = openchecks.DiscoveryRegistry()
    registry.register(lambda _: True, lambda _: [Check()])
    result = registry.gather(None)

    assert result
    assert len(result) == 1


def test_discovery_registry_gather_empty_plugins_success() -> None:
    registry = openchecks.DiscoveryRegistry()
    result = registry.gather(None)

    assert result is None


def test_discovery_registry_query_context_gather_return_some_success() -> None:
    registry = openchecks.DiscoveryRegistry()
    registry.register(lambda _: True, lambda _: [Check()])
    result = registry.gather(None)

    assert result is not None


def test_discovery_registry_query_context_gather_return_none_success() -> None:
    registry = openchecks.DiscoveryRegistry()
    registry.register(lambda _: False, lambda _: [Check()])
    result = registry.gather(None)

    assert result is None


@pytest.mark.asyncio
async def test_discovery_registry_register_and_gather_async_success() -> None:
    registry = openchecks.DiscoveryRegistry()
    registry.register_async(lambda _: True, lambda _: [AsyncCheck()])
    result = registry.gather_async(None)

    assert result
    assert len(result) == 1


@pytest.mark.asyncio
async def test_discovery_registry_gather_async_empty_plugins_success() -> None:
    registry = openchecks.DiscoveryRegistry()
    result = registry.gather_async(None)

    assert result is None


@pytest.mark.asyncio
async def test_discovery_registry_query_context_gather_async_return_some_success() -> (
    None
):
    registry = openchecks.DiscoveryRegistry()
    registry.register_async(lambda _: True, lambda _: [AsyncCheck()])
    result = registry.gather_async(None)

    assert result


@pytest.mark.asyncio
async def test_discovery_registry_query_context_gather_async_return_none_success() -> (
    None
):
    registry = openchecks.DiscoveryRegistry()
    registry.register_async(lambda _: False, lambda _: [AsyncCheck()])
    result = registry.gather_async(None)

    assert result is None
