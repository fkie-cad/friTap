"""Per-connection bidirectional byte buffer for stream reassembly."""


class StreamBuffer:
    """Per-connection bidirectional byte buffer for stream reassembly."""

    def __init__(self):
        self._write_buf = bytearray()  # request data (SSL_write = outgoing)
        self._read_buf = bytearray()   # response data (SSL_read = incoming)

    def append(self, data: bytes, direction: str, timestamp: float) -> None:
        if direction == "write":
            self._write_buf.extend(data)
        else:
            self._read_buf.extend(data)

    @property
    def request_data(self) -> bytes:
        return bytes(self._write_buf)

    @property
    def response_data(self) -> bytes:
        return bytes(self._read_buf)

    def consume_request(self, n: int) -> bytes:
        data = bytes(self._write_buf[:n])
        del self._write_buf[:n]
        return data

    def consume_response(self, n: int) -> bytes:
        data = bytes(self._read_buf[:n])
        del self._read_buf[:n]
        return data

    @property
    def has_request_data(self) -> bool:
        return len(self._write_buf) > 0

    @property
    def has_response_data(self) -> bool:
        return len(self._read_buf) > 0
