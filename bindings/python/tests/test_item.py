# ruff: noqa: D103,D100,S101

from __future__ import annotations

from typing import TYPE_CHECKING

import hypothesis
import openchecks
import pytest
from hypothesis import strategies

if TYPE_CHECKING:
    from typing import Optional


@hypothesis.given(
    value=strategies.integers(),
    other_value=strategies.integers(),
    type_hint=strategies.one_of(strategies.none(), strategies.text()),
)
def test_item(
    value: int,
    other_value: int,
    type_hint: Optional[str],
) -> None:
    item = openchecks.Item(value, type_hint)

    assert item.value() == value
    assert item.type_hint() == type_hint
    assert str(item) == str(value)
    assert repr(item) == f"Item({repr(value)})"

    assert (item == value) is False
    assert (item != value) is True

    with pytest.raises(TypeError):
        item < value  # type: ignore

    with pytest.raises(TypeError):
        item <= value  # type: ignore

    with pytest.raises(TypeError):
        item > value  # type: ignore

    with pytest.raises(TypeError):
        item >= value  # type: ignore

    other_item = openchecks.Item(other_value, type_hint)

    assert (item < other_item) == (value < other_value)
    assert (item <= other_item) == (value <= other_value)
    assert (item > other_item) == (value > other_value)
    assert (item >= other_item) == (value >= other_value)
    assert (item == other_item) == (value == other_value)
    assert (item != other_item) == (value != other_value)


@hypothesis.given(
    value=strategies.integers(),
    other_value=strategies.integers(),
    type_hint=strategies.one_of(strategies.none(), strategies.text()),
)
def test_item_reimplemented(
    value: int,
    other_value: int,
    type_hint: Optional[str],
) -> None:
    class Item(openchecks.Item):
        def __repr__(self) -> str:
            return f"debug_{self.value()}"

        def __str__(self) -> str:
            return f"display_{self.value()}"

        def __eq__(self, other: Item) -> bool:
            return self.value() != other.value()

        def __lt__(self, other: Item) -> bool:
            return self.value() > other.value()

    item = Item(value, type_hint)

    assert item.value() == value
    assert item.type_hint() == type_hint

    other_item = Item(other_value, type_hint)

    assert (item < other_item) == (value > other_value)
    assert (item > other_item) == (value < other_value)
    assert (item <= other_item) == (value >= other_value)
    assert (item >= other_item) == (value <= other_value)
    assert (item == other_item) == (value != other_value)
    assert (item != other_item) == (value == other_value)
