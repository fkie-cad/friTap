"""
ProtobufAnalyzer — detect and decode protobuf/gRPC content in HTTP flows.

Detects:
  - gRPC endpoints (application/grpc* content-type)
  - Protobuf message structures decoded from request/response bodies
  - Decode failures when content-type suggests protobuf but parsing fails
  - Unusual protobuf fields (high field numbers, deep nesting, oversized fields)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from friTap.analysis import Finding, Severity
from friTap.parsers.protobuf import (
    decode_raw,
    format_message,
    extract_grpc_messages,
    is_grpc_content_type,
    is_likely_protobuf,
    is_protobuf_content_type,
)

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.parsers.protobuf.wire import ProtobufMessage

logger = logging.getLogger("friTap.analysis.protobuf")

# Thresholds for unusual field detection
_MAX_NORMAL_FIELD_NUMBER = 1000
_MAX_NORMAL_NESTING_DEPTH = 10
_MAX_NORMAL_FIELD_SIZE = 1_048_576  # 1 MB


def _extract_grpc_method(flow: "Flow") -> str:
    """Extract the gRPC method path from the request URL."""
    if flow.request is not None and flow.request.url:
        return flow.request.url
    return ""


def _max_nesting_depth(msg: "ProtobufMessage", current: int = 0) -> int:
    """Compute the maximum nesting depth of a protobuf message tree."""
    max_depth = current
    for f in msg.fields:
        if f.sub_message is not None:
            child_depth = _max_nesting_depth(f.sub_message, current + 1)
            if child_depth > max_depth:
                max_depth = child_depth
    return max_depth


def _collect_field_info(msg: "ProtobufMessage") -> list[dict]:
    """Collect field numbers and wire types from the top-level message."""
    return [
        {"field_number": f.field_number, "wire_type": f.wire_type.name}
        for f in msg.fields
    ]


def _check_unusual_fields(
    msg: "ProtobufMessage",
    direction: str,
    flow: "Flow",
    source: str,
) -> list[Finding]:
    """Check for unusual protobuf characteristics and return findings."""
    findings: list[Finding] = []
    anomalies: list[str] = []

    high_fields = [f.field_number for f in msg.fields if f.field_number > _MAX_NORMAL_FIELD_NUMBER]
    if high_fields:
        anomalies.append(f"high field numbers: {high_fields[:5]}")

    depth = _max_nesting_depth(msg)
    if depth > _MAX_NORMAL_NESTING_DEPTH:
        anomalies.append(f"deep nesting: {depth} levels")

    oversized = [
        f.field_number
        for f in msg.fields
        if f.length_delimited is not None and len(f.length_delimited) > _MAX_NORMAL_FIELD_SIZE
    ]
    if oversized:
        anomalies.append(f"oversized fields (>1MB): field numbers {oversized[:5]}")

    if anomalies:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Unusual protobuf fields",
            description=f"Anomalies in {direction}: {'; '.join(anomalies)}",
            source=source,
            flow_id=flow.flow_id,
            evidence={
                "type": "protobuf_anomaly",
                "direction": direction,
                "anomalies": anomalies,
            },
        ))

    return findings


class ProtobufAnalyzer:
    """Analyzer that detects and decodes protobuf/gRPC content in HTTP flows."""

    name = "protobuf"

    def __init__(self, *, schema_path: str | None = None) -> None:
        self._schema_path = schema_path

    def analyze_flow(self, flow: "Flow") -> list[Finding]:
        findings: list[Finding] = []
        try:
            self._check_grpc(flow, findings)
            self._analyze_body(flow, "request", findings)
            self._analyze_body(flow, "response", findings)
        except Exception:
            logger.debug("Unexpected error analyzing flow %s", flow.flow_id, exc_info=True)
        from friTap.analysis.filtering import with_category
        return [with_category(f, "protocol") for f in findings]

    def _check_grpc(self, flow: "Flow", findings: list[Finding]) -> None:
        """Detect gRPC endpoints from content-type headers."""
        for direction in ("request", "response"):
            content_type = (
                flow.request_content_type if direction == "request"
                else flow.response_content_type
            )
            if is_grpc_content_type(content_type):
                grpc_method = _extract_grpc_method(flow)
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="gRPC endpoint detected",
                    description=(
                        f"gRPC {direction} to {flow.display_host}"
                        f"{(' ' + grpc_method) if grpc_method else ''}"
                    ),
                    source=self.name,
                    flow_id=flow.flow_id,
                    evidence={
                        "type": "grpc_endpoint",
                        "direction": direction,
                        "grpc_method": grpc_method,
                        "content_type": content_type,
                    },
                ))
                return  # one finding per flow is enough for gRPC detection

    def _analyze_body(self, flow: "Flow", direction: str, findings: list[Finding]) -> None:
        """Analyze a request or response body for protobuf content."""
        try:
            if direction == "request":
                body = flow.get_decompressed_request_body() if flow.request else b""
            else:
                body = flow.get_decompressed_response_body() if flow.response else b""
        except Exception:
            return

        if not body:
            return

        content_type = (
            flow.request_content_type if direction == "request"
            else flow.response_content_type
        )
        is_grpc = is_grpc_content_type(content_type)
        is_proto_ct = is_protobuf_content_type(content_type)

        # For gRPC, extract individual messages from the framing
        if is_grpc:
            try:
                messages = extract_grpc_messages(body, content_type)
            except Exception:
                messages = []
            if not messages:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="Protobuf decode failure",
                    description=f"gRPC {direction} body could not be decoded ({len(body)} bytes)",
                    source=self.name,
                    flow_id=flow.flow_id,
                    evidence={
                        "type": "protobuf_decode_failure",
                        "direction": direction,
                        "content_type": content_type,
                    },
                ))
                return
            for msg_bytes in messages:
                self._decode_and_report(msg_bytes, direction, content_type, flow, findings)
            return

        # For non-gRPC, check content-type or heuristic detection
        if is_proto_ct or is_likely_protobuf(body):
            try:
                self._decode_and_report(body, direction, content_type, flow, findings)
            except (ValueError, Exception):
                if is_proto_ct:
                    findings.append(Finding(
                        severity=Severity.LOW,
                        title="Protobuf decode failure",
                        description=(
                            f"{direction} content-type suggests protobuf but "
                            f"body does not appear to be valid ({len(body)} bytes)"
                        ),
                        source=self.name,
                        flow_id=flow.flow_id,
                        evidence={
                            "type": "protobuf_decode_failure",
                            "direction": direction,
                            "content_type": content_type,
                        },
                    ))

    def _decode_and_report(
        self,
        data: bytes,
        direction: str,
        content_type: str,
        flow: "Flow",
        findings: list[Finding],
    ) -> None:
        """Attempt to decode protobuf data and produce findings."""
        try:
            msg = decode_raw(data)
        except (ValueError, IndexError):
            findings.append(Finding(
                severity=Severity.LOW,
                title="Protobuf decode failure",
                description=f"Failed to decode {direction} protobuf ({len(data)} bytes)",
                source=self.name,
                flow_id=flow.flow_id,
                evidence={
                    "type": "protobuf_decode_failure",
                    "direction": direction,
                    "content_type": content_type,
                },
            ))
            return

        if not msg.fields:
            return

        formatted = format_message(msg)
        fields = _collect_field_info(msg)

        findings.append(Finding(
            severity=Severity.INFO,
            title="Protobuf structure decoded",
            description=f"Decoded {len(msg.fields)} top-level fields from {direction} ({len(data)} bytes)",
            source=self.name,
            flow_id=flow.flow_id,
            evidence={
                "type": "protobuf_decoded",
                "direction": direction,
                "fields": fields,
                "formatted": formatted[:2000],  # cap for very large messages
                "content_type": content_type,
                "size": len(data),
            },
        ))

        # Check for unusual characteristics
        findings.extend(_check_unusual_fields(msg, direction, flow, self.name))
