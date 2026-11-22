"""ECH_SECRET / ECH_CONFIG keylog lines must be written verbatim by the host."""
import io

import pytest

from friTap.output.formatters import write_keylog_line

CLIENT_RANDOM = "ab" * 32


@pytest.mark.parametrize("label", ["ECH_SECRET", "ECH_CONFIG"])
def test_ech_lines_are_written_verbatim(label):
    line = f"{label} {CLIENT_RANDOM} {'cd' * 48}"
    buffer = io.StringIO()
    write_keylog_line(buffer, line)
    assert buffer.getvalue() == line + "\n"


def test_ech_labels_are_known_tls_keylog_labels():
    """NSS writes ECH_SECRET/ECH_CONFIG as <label> <client_random> <hex>: the client_random
    must be extracted and redacted JSON must name the label instead of "unknown"."""
    from friTap.output.key_material import KNOWN_KEYLOG_LABELS
    from friTap.pipeline import TLS_KEYLOG_LABELS
    for label in ("ECH_SECRET", "ECH_CONFIG"):
        assert label in TLS_KEYLOG_LABELS
        assert label in KNOWN_KEYLOG_LABELS


def test_tls_keylog_label_copies_stay_equal():
    from friTap.offline.tls.keylog import TLS_KEYLOG_LABELS as offline_labels
    from friTap.output.key_material import KNOWN_KEYLOG_LABELS
    from friTap.pipeline import TLS_KEYLOG_LABELS as pipeline_labels
    from friTap.tls_keylog_labels import TLS_KEYLOG_LABELS as canonical
    assert offline_labels is canonical
    assert pipeline_labels is canonical
    assert canonical <= KNOWN_KEYLOG_LABELS
