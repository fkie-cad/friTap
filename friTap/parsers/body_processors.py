"""Composable body processing pipeline for flow content rendering."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class BodyProcessor(Protocol):
    """Protocol for body content processors."""

    def process(self, body: bytes, content_type: str, encoding: str) -> tuple[bytes, str, str]:
        """Process body content.

        Args:
            body: Raw body bytes
            content_type: MIME content type (e.g. "application/json")
            encoding: Content-Encoding value (e.g. "gzip")

        Returns:
            Tuple of (processed_body, updated_content_type, error_message).
            Error is empty string on success.
        """
        ...


class DecompressProcessor:
    """Decompresses body based on Content-Encoding header."""

    def process(self, body: bytes, content_type: str, encoding: str) -> tuple[bytes, str, str]:
        if not encoding:
            return body, content_type, ""
        from friTap.parsers.decompress import decompress_body
        decompressed, err = decompress_body(body, encoding)
        return decompressed, content_type, err


class BodyPipeline:
    """Chains multiple BodyProcessors in order."""

    def __init__(self) -> None:
        self._processors: list[BodyProcessor] = []

    def add(self, processor: BodyProcessor) -> None:
        """Add a processor to the end of the chain."""
        self._processors.append(processor)

    def process(self, body: bytes, content_type: str = "", encoding: str = "") -> tuple[bytes, str, str]:
        """Run body through all processors in order.

        Returns (final_body, final_content_type, first_error).
        Continues through all processors even on error; records the first error.
        """
        first_error = ""
        for proc in self._processors:
            body, content_type, err = proc.process(body, content_type, encoding)
            if err and not first_error:
                first_error = err
        return body, content_type, first_error


def create_default_pipeline() -> BodyPipeline:
    """Create the default body processing pipeline with decompression."""
    pipeline = BodyPipeline()
    pipeline.add(DecompressProcessor())
    return pipeline
