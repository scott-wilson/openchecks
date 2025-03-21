from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from typing import Callable, Iterable, List, Optional, Tuple

T = TypeVar("T")

class Status(enum.Enum):
    Pending = enum.auto()
    Skipped = enum.auto()
    Passed = enum.auto()
    Warning = enum.auto()
    Failed = enum.auto()
    SystemError = enum.auto()

    def is_pending(self) -> bool: ...
    def has_passed(self) -> bool: ...
    def has_failed(self) -> bool: ...

class Item(Generic[T]):
    def __init__(
        self,
        value: T,
        type_hint: Optional[str] = None,
    ) -> None: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __eq__(self, other: Item[T]) -> bool: ...
    def __ne__(self, other: Item[T]) -> bool: ...
    def __lt__(self, other: Item[T]) -> bool: ...
    def __le__(self, other: Item[T]) -> bool: ...
    def __gt__(self, other: Item[T]) -> bool: ...
    def __ge__(self, other: Item[T]) -> bool: ...
    def value(self) -> T: ...
    def type_hint(self) -> Optional[str]: ...

class CheckResult(Generic[T]):
    def __init__(
        self,
        status: Status,
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
        error: Optional[BaseException] = None,
    ) -> None: ...
    def status(self) -> Status: ...
    def message(self) -> str: ...
    def items(self) -> Optional[List[Item[T]]]: ...
    def can_fix(self) -> bool: ...
    def can_skip(self) -> bool: ...
    def error(self) -> Optional[CheckError]: ...
    def check_duration(self) -> float: ...
    def fix_duration(self) -> float: ...
    @staticmethod
    def passed(
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
    ) -> CheckResult: ...
    @staticmethod
    def skipped(
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
    ) -> CheckResult: ...
    @staticmethod
    def warning(
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
    ) -> CheckResult: ...
    @staticmethod
    def failed(
        message: str,
        items: Optional[List[Item[T]]] = None,
        can_fix: bool = False,
        can_skip: bool = False,
    ) -> CheckResult: ...

class CheckHint(enum.Flag):
    NONE = 0b0
    AUTO_FIX = enum.auto()

    @staticmethod
    def all() -> CheckHint: ...

class CheckMetadata(Generic[T]):
    def title(self) -> str: ...
    def description(self) -> str: ...
    def hint(self) -> CheckHint: ...

class BaseCheck(CheckMetadata, Generic[T]):
    def check(self) -> CheckResult[T]: ...
    def auto_fix(self) -> None: ...

class AsyncBaseCheck(CheckMetadata, Generic[T]):
    async def async_check(self) -> CheckResult[T]: ...
    async def async_auto_fix(self) -> None: ...

class CheckError(Exception): ...

class DiscoveryRegistry(Generic[T]):
    def register(
        self, query: Callable[[T], bool], generator: Callable[[T], list[BaseCheck]]
    ) -> None: ...
    def register_async(
        self, query: Callable[[T], bool], generator: Callable[[T], list[AsyncBaseCheck]]
    ) -> None: ...
    def gather(self, context: T) -> Optional[list[BaseCheck]]: ...
    def gather_async(self, context: T) -> Optional[list[AsyncBaseCheck]]: ...

def run(check: BaseCheck[T]) -> CheckResult[T]: ...
def auto_fix(check: BaseCheck[T]) -> CheckResult[T]: ...
async def async_run(check: AsyncBaseCheck[T]) -> CheckResult[T]: ...
async def async_auto_fix(check: AsyncBaseCheck[T]) -> CheckResult[T]: ...

class BaseScheduler(Generic[T]):
    def run(
        self, checks: Iterable[BaseCheck[T]]
    ) -> List[Tuple[BaseCheck[T], CheckResult[T]]]: ...
    def auto_fix(
        self, check: Iterable[BaseCheck[T]]
    ) -> List[Tuple[BaseCheck[T], CheckResult[T]]]: ...

class AsyncBaseScheduler(Generic[T]):
    async def async_run(
        self, checks: Iterable[AsyncBaseCheck[T]]
    ) -> List[Tuple[BaseCheck[T], CheckResult[T]]]: ...
    async def async_auto_fix(
        self, check: Iterable[AsyncBaseCheck[T]]
    ) -> List[Tuple[BaseCheck[T], CheckResult[T]]]: ...

class Scheduler(BaseScheduler[T]): ...
