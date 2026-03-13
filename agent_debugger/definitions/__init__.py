"""Extraction definitions for debugger-based key extraction."""

from .base import (
    StructField,
    StructExtraction,
    BreakpointSpec,
    ExtractionDefinition,
    resolve_offset,
)
from .ssh_openssh import SSH_OPENSSH
from .ipsec_strongswan import IPSEC_STRONGSWAN

__all__ = [
    "StructField",
    "StructExtraction",
    "BreakpointSpec",
    "ExtractionDefinition",
    "resolve_offset",
    "SSH_OPENSSH",
    "IPSEC_STRONGSWAN",
]
