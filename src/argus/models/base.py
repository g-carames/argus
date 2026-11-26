"""Strict immutable records shared by backend components."""

from dataclasses import dataclass, fields
from enum import StrEnum
from functools import lru_cache
from math import isfinite
from pathlib import PurePosixPath
from types import UnionType
from typing import get_args, get_origin, get_type_hints


@lru_cache
def _hints(cls: type) -> dict:
    return get_type_hints(cls)


def _matches(value: object, hint: object) -> bool:
    origin = get_origin(hint)
    if origin is UnionType:
        return any(_matches(value, item) for item in get_args(hint))
    if origin is tuple:
        args = get_args(hint)
        return isinstance(value, tuple) and all(_matches(item, args[0]) for item in value)
    if hint is float:
        return type(value) in (int, float) and isfinite(value)
    if hint in (str, int, bool, type(None)):
        return type(value) is hint
    return isinstance(value, hint)


@dataclass(frozen=True, kw_only=True)
class Record:
    """Validate types without coercion; errors never echo supplied values."""

    def __post_init__(self) -> None:
        for field in fields(self):
            if not _matches(getattr(self, field.name), _hints(type(self))[field.name]):
                raise ValueError(f"{type(self).__name__}.{field.name}: invalid type or value")
        self.validate()

    def validate(self) -> None:
        """Subclasses enforce semantic invariants."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def nonempty(value: str) -> None:
    require(bool(value.strip()), "nonempty text required")


def relative_path(value: str) -> None:
    path = PurePosixPath(value)
    require(bool(value) and value != "." and not path.is_absolute()
            and ".." not in path.parts and "\\" not in value and ":" not in value
            and all(ord(char) >= 32 for char in value)
            and str(path) == value, "canonical repository-relative path required")


def unique(values: tuple[str, ...]) -> None:
    require(len(values) == len(set(values)), "duplicate identifiers")


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Provenance(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    HEURISTIC = "heuristic"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(StrEnum):
    ARCHITECTURE = "architecture"
    SECURITY = "security"
    CREDENTIALS = "credentials"
    MAINTAINABILITY = "maintainability"
    DEPENDENCY_HEALTH = "dependency_health"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance_scalability"
    AI = "ai_specific"
    COST = "cost_efficiency"


class Capability(StrEnum):
    PARSING = "syntax_parsing"
    SYMBOLS = "symbol_extraction"
    STRUCTURE = "structural_analysis"
    DEPENDENCIES = "dependency_extraction"
    RESOLUTION = "dependency_resolution"
    COMPLEXITY = "complexity_analysis"
    ARCHITECTURE = "architectural_rules"
    SECURITY = "security_rules"
    CREDENTIALS = "credential_detection"
    FRAMEWORK = "framework_analysis"
    AI = "ai_specific_analysis"
    CONFIGURATION = "configuration_analysis"
    CONTROL_FLOW = "control_flow_analysis"
    DATA_FLOW = "local_data_flow_analysis"
    SUMMARIES = "function_operation_summaries"
    BOUNDS = "collection_bound_analysis"
    TAINT = "source_to_sink_tracking"


class Status(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    EXCLUDED = "excluded"
    FAILED = "failed"
    DISABLED = "disabled"
    UNCLASSIFIED = "unclassified"
