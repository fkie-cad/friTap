import os
import stat

import pytest

from friTap.sinks._fifo import cleanup_fifo, make_fifo

pytestmark = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")


def test_make_and_cleanup_fifo():
    tmpdir, path = make_fifo("x.pcapng")
    assert os.path.basename(path) == "x.pcapng"
    assert stat.S_ISFIFO(os.stat(path).st_mode)
    cleanup_fifo(path, tmpdir)
    assert not os.path.exists(tmpdir)
    cleanup_fifo(path, tmpdir)  # idempotent
    cleanup_fifo(None, None)
