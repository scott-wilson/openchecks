# ruff: noqa: D103,D100,S101

from __future__ import annotations

from typing import TYPE_CHECKING

import atheris
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
@atheris.instrument_func
def fuzz(
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


if __name__ == "__main__":
    import sys

    atheris.Setup(sys.argv, atheris.instrument_func(fuzz.hypothesis.fuzz_one_input))
    atheris.Fuzz()
