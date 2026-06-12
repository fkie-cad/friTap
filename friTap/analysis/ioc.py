"""
IocAnalyzer — extract Indicators of Compromise from HTTP flows.

Extracts:
  - Domains and IP addresses from connection metadata and HTTP headers
  - Full URLs from requests
  - File hashes (SHA-256) of response bodies
  - User-Agent strings
  - Email addresses found in traffic
  - Server software versions from response headers
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import TYPE_CHECKING

from friTap.analysis import Finding, Severity

if TYPE_CHECKING:
    from friTap.flow.models import Flow


# IPv4 address pattern (strict: no leading zeros, valid octets)
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$")


def _is_private_ip(addr: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def _is_valid_domain(domain: str) -> bool:
    """Basic check that a string looks like a valid domain name."""
    if not domain or len(domain) > 253:
        return False
    if "." not in domain:
        return False
    parts = domain.split(".")
    if len(parts[-1]) < 2:
        return False
    return all(
        bool(part) and _DOMAIN_LABEL_RE.match(part) is not None
        for part in parts
    )


class IocAnalyzer:
    """Analyzer that extracts Indicators of Compromise from HTTP flows."""

    name = "ioc"

    def __init__(self, *, include_private_ips: bool = False) -> None:
        self._include_private_ips = include_private_ips

    def analyze_flow(self, flow: "Flow") -> list[Finding]:
        findings: list[Finding] = []
        resp_body = flow.get_decompressed_response_body() if flow.response else b""
        self._extract_connection_iocs(flow, findings)
        self._extract_header_iocs(flow, findings)
        self._extract_url_ioc(flow, findings)
        self._extract_body_hashes(flow, resp_body, findings)
        self._extract_body_iocs(flow, resp_body, findings)
        return [self._categorize(f) for f in findings]

    @staticmethod
    def _categorize(finding: Finding) -> Finding:
        """Tag an IOC finding with its category: emails are PII, the rest network."""
        from friTap.analysis.filtering import with_category

        if finding.evidence.get("type") == "email":
            return with_category(finding, "pii", compliance=["GDPR", "CCPA"])
        return with_category(finding, "network")

    def _extract_connection_iocs(self, flow: "Flow", findings: list[Finding]) -> None:
        """Extract IOCs from connection metadata (dst IP, dst port)."""
        if flow.dst_addr:
            try:
                ipaddress.ip_address(flow.dst_addr)
                is_ip = True
            except ValueError:
                is_ip = False

            if is_ip:
                if self._include_private_ips or not _is_private_ip(flow.dst_addr):
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title=f"Destination IP: {flow.dst_addr}",
                        description=f"Connection to {flow.dst_addr}:{flow.dst_port}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        evidence={
                            "type": "ip",
                            "value": flow.dst_addr,
                            "port": flow.dst_port,
                            "direction": "destination",
                        },
                    ))

    def _extract_header_iocs(self, flow: "Flow", findings: list[Finding]) -> None:
        """Extract IOCs from HTTP headers."""
        # Request headers
        if flow.request is not None:
            host = flow.request.host or flow.get_request_header("host")
            if host:
                # Strip port if present
                clean_host = host.split(":")[0]
                if _is_valid_domain(clean_host):
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title=f"Domain: {clean_host}",
                        description=f"HTTP request to domain {clean_host}",
                        source=self.name,
                        flow_id=flow.flow_id,
                        evidence={
                            "type": "domain",
                            "value": clean_host,
                            "port": flow.dst_port,
                        },
                    ))

            # User-Agent
            ua = flow.get_request_header("user-agent")
            if ua:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="User-Agent string",
                    description=f"User-Agent: {ua[:100]}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    evidence={
                        "type": "user-agent",
                        "value": ua,
                        "host": flow.display_host,
                    },
                ))

            # Referer (can reveal related infrastructure)
            referer = flow.get_request_header("referer")
            if referer:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Referer URL",
                    description=f"Referer: {referer[:100]}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    evidence={
                        "type": "url",
                        "value": referer,
                        "context": "referer",
                    },
                ))

        # Response headers
        if flow.response is not None:
            # Server header
            server = flow.get_response_header("server")
            if server:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title=f"Server: {server}",
                    description=f"Server software identified: {server}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    evidence={
                        "type": "server",
                        "value": server,
                        "host": flow.display_host,
                    },
                ))

            # Location header (redirects reveal infrastructure)
            location = flow.get_response_header("location")
            if location:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Redirect URL",
                    description=f"Redirect to: {location[:100]}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    evidence={
                        "type": "url",
                        "value": location,
                        "context": "redirect",
                    },
                ))

            # Set-Cookie domain attributes
            set_cookie = flow.get_response_header("set-cookie")
            if set_cookie:
                domain_match = re.search(r"domain=\.?([^;]+)", set_cookie, re.IGNORECASE)
                if domain_match:
                    cookie_domain = domain_match.group(1).strip()
                    if _is_valid_domain(cookie_domain):
                        findings.append(Finding(
                            severity=Severity.INFO,
                            title=f"Cookie domain: {cookie_domain}",
                            description=f"Set-Cookie with domain={cookie_domain}",
                            source=self.name,
                            flow_id=flow.flow_id,
                            evidence={
                                "type": "domain",
                                "value": cookie_domain,
                                "context": "cookie_domain",
                            },
                        ))

    def _extract_url_ioc(self, flow: "Flow", findings: list[Finding]) -> None:
        """Extract the full request URL as an IOC."""
        if flow.request is None:
            return

        host = flow.request.host or flow.get_request_header("host") or flow.dst_addr
        url = flow.request.url or "/"
        method = flow.request.method or "GET"

        if host:
            full_url = f"https://{host}{url}"
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"{method} {host}{url[:60]}",
                description=f"HTTP request: {method} {full_url}",
                source=self.name,
                flow_id=flow.flow_id,
                evidence={
                    "type": "url",
                    "value": full_url,
                    "method": method,
                    "status": flow.display_status,
                },
            ))

    def _extract_body_hashes(self, flow: "Flow", body: bytes, findings: list[Finding]) -> None:
        """Compute SHA-256 hash of response bodies (for malware/file IOCs)."""
        if not body or len(body) < 32:
            return

        sha256 = hashlib.sha256(body).hexdigest()
        content_type = flow.response_content_type

        findings.append(Finding(
            severity=Severity.INFO,
            title="Response body hash (SHA-256)",
            description=f"SHA-256 of response from {flow.display_host} ({len(body)} bytes)",
            source=self.name,
            flow_id=flow.flow_id,
            evidence={
                "type": "hash",
                "algorithm": "sha256",
                "value": sha256,
                "size": len(body),
                "content_type": content_type,
                "host": flow.display_host,
            },
        ))

    def _extract_body_iocs(self, flow: "Flow", body: bytes, findings: list[Finding]) -> None:
        """Extract IPs and emails from response bodies."""
        if not body:
            return

        content_type = flow.response_content_type.lower()
        if not any(t in content_type for t in ("json", "text", "html", "xml", "javascript")):
            return

        text = body.decode("utf-8", errors="replace")
        seen_ips: set[str] = set()
        for match in _IPV4_PATTERN.finditer(text):
            ip = match.group(0)
            if ip not in seen_ips and (self._include_private_ips or not _is_private_ip(ip)):
                seen_ips.add(ip)
                findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"IP in response body: {ip}",
                    description=f"IP address {ip} found in response from {flow.display_host}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    confidence=0.6,
                    evidence={
                        "type": "ip",
                        "value": ip,
                        "context": "response_body",
                        "host": flow.display_host,
                    },
                ))

        # Extract emails from response body
        seen_emails: set[str] = set()
        for match in _EMAIL_PATTERN.finditer(text):
            email = match.group(0)
            if email not in seen_emails:
                seen_emails.add(email)
                findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"Email in response: {email}",
                    description=f"Email address found in response from {flow.display_host}",
                    source=self.name,
                    flow_id=flow.flow_id,
                    confidence=0.7,
                    evidence={
                        "type": "email",
                        "value": email,
                        "context": "response_body",
                        "host": flow.display_host,
                    },
                ))
