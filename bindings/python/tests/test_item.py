from __future__ import annotations

from typing import TYPE_CHECKING
import hypothesis
from hypothesis import strategies
import pychecks

if TYPE_CHECKING:
    from typing import Optional, Callable


@hypothesis.given(
    value=strategies.integers(),
    other_value=strategies.integers(),
    type_hint=strategies.one_of(strategies.none(), strategies.text()),
    debug_fn=strategies.one_of(
        strategies.none(), strategies.just(lambda x: f"debug_{x}")
    ),
    display_fn=strategies.one_of(
        strategies.none(), strategies.just(lambda x: f"display_{x}")
    ),
    lt_fn=strategies.one_of(strategies.none(), strategies.just(lambda x, y: x > y)),
    eq_fn=strategies.one_of(strategies.none(), strategies.just(lambda x, y: x != y)),
)
def test_item(
    value: int,
    other_value: int,
    type_hint: Optional[str],
    debug_fn: Optional[Callable[[int], str]],
    display_fn: Optional[Callable[[int], str]],
    lt_fn: Optional[Callable[[int, int], bool]],
    eq_fn: Optional[Callable[[int, int], bool]],
):
    item = pychecks.Item(value, type_hint, debug_fn, display_fn, lt_fn, eq_fn)

    assert item.value() == value
    assert item.type_hint() == type_hint

    if debug_fn is None:
        assert repr(item) == f"Item({repr(value)})"
    else:
        assert repr(item) == f"Item(debug_{value})"

    if display_fn is None:
        assert str(item) == str(value)
    else:
        assert str(item) == f"display_{value}"

    other_item = pychecks.Item(
        other_value, type_hint, debug_fn, display_fn, lt_fn, eq_fn
    )

    if lt_fn is None:
        assert (item < other_item) == (value < other_value)
    else:
        assert (item < other_item) == (value > other_value)

    if eq_fn is None:
        assert (item == other_item) == (value == other_value)
    else:
        assert (item == other_item) == (value != other_value)
