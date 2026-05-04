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

from .evaluator import FilterEngine
from .errors import FilterSyntaxError, FilterEvalError
from .fields import all_field_names, FIELD_REGISTRY, is_field_prefix
from .parser import parse_filter

__all__ = [
    "FilterEngine",
    "FilterSyntaxError",
    "FilterEvalError",
    "all_field_names",
    "parse_filter",
    "FIELD_REGISTRY",
    "is_field_prefix",
]
