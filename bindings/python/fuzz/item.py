from __future__ import annotations

import atheris
import hypothesis
import pytest
from hypothesis import strategies

import openchecks


@hypothesis.given(
    value=strategies.integers(),
    other_value=strategies.integers(),
    type_hint=strategies.one_of(strategies.none(), strategies.text()),
)
@atheris.instrument_func
def fuzz(
    value: int,
    other_value: int,
    type_hint: str | None,
) -> None:
    item = openchecks.Item(value, type_hint)

    assert item.value() == value
    assert item.type_hint() == type_hint
    assert str(item) == str(value)
    assert repr(item) == f"Item({value!r})"

    assert (item == value) is False
    assert (item != value) is True

    with pytest.raises(TypeError):
        item < value  # type: ignore  # noqa: B015, PGH003

    with pytest.raises(TypeError):
        item <= value  # type: ignore  # noqa: B015, PGH003

    with pytest.raises(TypeError):
        item > value  # type: ignore  # noqa: B015, PGH003

    with pytest.raises(TypeError):
        item >= value  # type: ignore  # noqa: B015, PGH003

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
