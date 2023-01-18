from __future__ import annotations

from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:  # pragma: no cover
    from typing import Optional

T = TypeVar("T")

__all__ = [
    "Item",
]


class Item(Generic[T]):
    """
    The item is a wrapper to make a result item more user interface friendly.

    Result items represent the objects that caused a result. For example, if a
    check failed because the bones in a character rig are not properly named,
    then the items would contain the bones that are named incorrectly.

    The item wrapper makes the use of items user interface friendly because it
    implements item sorting and a string representation of the item.

    Args:
        value: The wrapped value
        type_hint: A hint to add extra context to the value.
            For example, if the value is a string, and that string represents a
            scene path, then a user interface could use that knowledge to
            select the scene path in the application. Default to the type
            having no meaning outside of itself.
    """

    def __init__(
        self,
        value: T,
        type_hint: Optional[str] = None,
    ) -> None:
        self.__value = value
        self.__type_hint = type_hint

    def __str__(self) -> str:
        return str(self.__value)

    def __repr__(self) -> str:
        return f"Item({self.value()!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Item):
            return NotImplemented

        return bool(self.value() == other.value())

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, Item):
            return NotImplemented

        return not (self == other)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Item):
            return NotImplemented

        return bool(self.value() < other.value())

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Item):
            return NotImplemented

        return not (self > other)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Item):
            return NotImplemented

        return other < self

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Item):
            return NotImplemented

        return not (self < other)

    def value(self) -> T:
        """The value that is wrapped.

        Returns:
            The wrapped value.
        """
        return self.__value

    def type_hint(self) -> Optional[str]:
        """A type hint can be used to add a hint to a system that the given
        type represents something else. For example, the value could be a
        string, but this is a scene path.

        A user interface could use this hint to select the item in the
        application.

        Returns:
            The type hint.
        """
        return self.__type_hint
