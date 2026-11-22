"""Demo friTap viewer extension (embedding mode C).

``register()`` is the zero-argument entry-point target of the
``fritap.ui_extensions`` group. It only uses the ``friTap.ui`` facade.
"""

from friTap.ui import (
    BaseAnalyzer,
    BodyDecoderSpec,
    DetailTabSpec,
    Finding,
    FlowColumnSpec,
    LayerFieldSpec,
    Severity,
    register_analyzer,
    register_body_decoder,
    register_detail_tab,
    register_filter_field,
    register_flow_column,
)

LARGE_BODY_BYTES = 1024 * 1024
ANALYZER_NAME = "demo-large-body"


def _body_of(parsed) -> bytes:
    return (getattr(parsed, "body", b"") or b"") if parsed is not None else b""


def render_demo_tab(flow):
    """Detail tab: short summary, or None (tab hidden) when there is no data."""
    request, response = getattr(flow, "request", None), getattr(flow, "response", None)
    if request is None and response is None:
        return None
    return (f"{flow.src_addr}:{flow.src_port} -> {flow.dst_addr}:{flow.dst_port}\n"
            f"request body: {len(_body_of(request))} bytes\n"
            f"response body: {len(_body_of(response))} bytes")


def bytes_column(summary_row) -> str:
    """Flow-list cell from the lightweight summary row (no bodies loaded)."""
    return str(getattr(summary_row, "total_bytes", 0) or 0)


def decode_length_summary(body: bytes, headers) -> list:
    """Body decoder: byte count, printable ratio and a hex head."""
    printable = sum(1 for b in body if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / len(body) if body else 0.0
    return [f"{len(body)} bytes, {ratio:.0%} printable",
            f"hex head: {body[:16].hex(' ')}"]


class LargeBodyAnalyzer:
    """Analyzer contract (``BaseAnalyzer``): ``name`` + ``analyze_flow(flow)``."""

    name = ANALYZER_NAME

    def analyze_flow(self, flow) -> list:
        findings = []
        for direction in ("request", "response"):
            size = len(_body_of(getattr(flow, direction, None)))
            if size >= LARGE_BODY_BYTES:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Large body",
                    description=f"{direction} body is {size} bytes",
                    source=self.name,
                    flow_id=flow.flow_id,
                    evidence={"direction": direction, "size": size},
                ))
        return findings


def make_analyzer(**_ignored) -> BaseAnalyzer:
    return LargeBodyAnalyzer()


def register() -> None:
    register_detail_tab(DetailTabSpec(id="demo", label="Demo", render=render_demo_tab))
    register_flow_column(FlowColumnSpec(key="demo_bytes", label="Bytes", width=10,
                                        value=bytes_column))
    register_body_decoder(BodyDecoderSpec(name="demo_length", label="Length summary",
                                          decode=decode_length_summary))
    # A filter field is a path into the layer dicts stored in the .tap
    # (meta["layers"]), not a computation. The tls layer dict carries "version"
    # (friTap.flow.layers.TlsLayer.to_dict), so this field is real for any
    # capture with TLS metadata. Fields must be registered before the .tap is
    # read; the viewer constructor calls load_extensions() first.
    register_filter_field(LayerFieldSpec(
        field="demo.tls_version", layers=("tls",), path="version",
        value_type="str", description="TLS version (demo extension)"))
    register_analyzer(ANALYZER_NAME, make_analyzer)
