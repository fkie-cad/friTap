"""Display filter engine for friTap — Wireshark-like filter expressions.

Usage:
    from friTap.filter import FilterEngine

    engine = FilterEngine("http.response.code >= 400 and ip.dst == 10.0.0.1")
    if engine.matches(flow):
        print("Flow matches filter")

    # Validate without creating engine
    error = FilterEngine.validate("bad syntax ===")
    if error:
        print(f"Invalid: {error}")
"""

from .errors import FilterEvalError, FilterSyntaxError, UnknownFieldError
from .evaluator import FilterEngine
from .fields import FIELD_REGISTRY, all_field_names, get_field, is_field_prefix
from .parser import parse_filter

__all__ = [
    "FilterEngine",
    "FilterSyntaxError",
    "FilterEvalError",
    "UnknownFieldError",
    "get_field",
    "all_field_names",
    "parse_filter",
    "FIELD_REGISTRY",
    "is_field_prefix",
]
