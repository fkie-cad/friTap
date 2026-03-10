#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Library inspector for friTap.

Uses tlsLibHunter to detect and extract TLS/SSL libraries
in a target process via memory pattern scanning, fingerprinting,
and export analysis.
"""

class LibraryInspector:
    """Inspects loaded libraries in a target process using tlsLibHunter."""

    @staticmethod
    def inspect(config, logger) -> str:
        """Scan for TLS libraries using tlsLibHunter.

        Args:
            config: A FriTapConfig instance.
            logger: A logging.Logger instance.

        Returns:
            A multi-line string with detection results, or an error string.
        """
        try:
            from tlslibhunter import TLSLibHunter
            hc = LibraryInspector._build_hunter_config(config)
            with TLSLibHunter.from_config(hc) as hunter:
                result = hunter.scan()
            return LibraryInspector._format_scan_result(result)
        except Exception as e:
            logger.error("Error during library inspection: %s", e)
            return f"Error: Failed to inspect libraries - {e}"

    @staticmethod
    def extract_libraries(config, logger, output_dir) -> str:
        """Extract detected TLS libraries to disk.

        Args:
            config: A FriTapConfig instance.
            logger: A logging.Logger instance.
            output_dir: Directory path where extracted libraries are saved.

        Returns:
            A multi-line string with extraction results, or an error string.
        """
        try:
            from tlslibhunter import TLSLibHunter
            hc = LibraryInspector._build_hunter_config(config)
            with TLSLibHunter.from_config(hc) as hunter:
                scan_result = hunter.scan()
                if not scan_result.libraries:
                    return LibraryInspector._format_scan_result(scan_result) + "\n\nNo libraries to extract."
                extractions = hunter.extract(scan_result, output_dir=output_dir)
            lines = [LibraryInspector._format_scan_result(scan_result)]
            lines.append("")
            lines.append(LibraryInspector._format_extraction_results(extractions))
            return "\n".join(lines)
        except Exception as e:
            logger.error("Error during library extraction: %s", e)
            return f"Error: Failed to extract libraries - {e}"

    @staticmethod
    def scan_to_dicts(config, logger) -> list:
        """Run tlsLibHunter scan and return results as serializable dicts."""
        try:
            from tlslibhunter import TLSLibHunter
            hc = LibraryInspector._build_hunter_config(config)
            with TLSLibHunter.from_config(hc) as hunter:
                result = hunter.scan()
            return [
                {
                    "name": lib.name,
                    "path": lib.path,
                    "base_address": lib.base_address,
                    "library_type": lib.library_type,
                    "matched_exports": lib.matched_exports,
                    "detected_version": lib.detected_version,
                }
                for lib in result.libraries
            ]
        except Exception as e:
            logger.warning("Library pre-scan failed: %s", e)
            return []

    @staticmethod
    def _build_hunter_config(config):
        """Map FriTapConfig fields to a HunterConfig."""
        from tlslibhunter import HunterConfig
        mobile = config.device.mobile
        kwargs = {
            "target": config.target,
            "spawn": config.device.spawn,
            "verbose": config.debug,
        }

        if mobile is True:
            kwargs["mobile"] = True
        elif mobile:
            # String value means a device serial/ID
            kwargs["mobile"] = True
            kwargs["serial"] = str(mobile)

        if config.device.host:
            kwargs["host"] = config.device.host

        return HunterConfig(**kwargs)

    @staticmethod
    def _format_scan_result(result) -> str:
        """Format a ScanResult into a human-readable string."""
        lines = ["=== [ TLS/SSL Library Detection (tlsLibHunter) ] ==="]
        lines.append(f"Target:           {result.target}")
        lines.append(f"Platform:         {result.platform}")
        lines.append(f"Modules scanned:  {result.total_modules_scanned}")
        lines.append(f"Scan duration:    {result.scan_duration_seconds:.2f}s")
        lines.append(f"Libraries found:  {result.tls_library_count}")

        if result.errors:
            lines.append("")
            lines.append("Errors:")
            for err in result.errors:
                lines.append(f"  [!] {err}")

        if result.libraries:
            lines.append("")
            for lib in result.libraries:
                lines.append(f"  {lib.library_type:<18} {lib.name}")
                lines.append(f"    Base:           {lib.base_address}")
                lines.append(f"    Size:           {lib.size} bytes")
                if lib.path:
                    lines.append(f"    Path:           {lib.path}")
                if lib.detected_version:
                    lines.append(f"    Version:        {lib.detected_version}")
                lines.append(f"    Classification: {lib.classification}")
                if lib.matched_exports:
                    preview = lib.matched_exports[:5]
                    lines.append(f"    Exports:        {', '.join(preview)}")
                    if len(lib.matched_exports) > 5:
                        lines.append(f"                    ... and {len(lib.matched_exports) - 5} more")

        return "\n".join(lines)

    @staticmethod
    def _format_extraction_results(extractions) -> str:
        """Format a list of ExtractionResult into a human-readable string."""
        lines = ["=== [ Library Extraction Results ] ==="]
        for ext in extractions:
            marker = "+" if ext.success else "x"
            lines.append(f"  [{marker}] {ext.library.name}")
            if ext.success:
                lines.append(f"      Method: {ext.method}")
                lines.append(f"      Output: {ext.output_path}")
                lines.append(f"      Size:   {ext.size_bytes} bytes")
            else:
                lines.append(f"      Error:  {ext.error}")
        return "\n".join(lines)
