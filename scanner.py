from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable


ALLOWED_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)

COMMON_PORTS = (
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138,
    139, 143, 161, 389, 443, 445, 465, 514, 587, 636, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    9200, 27017
)

PORT_CATALOG = {
    20: ("FTP Data", "medium", "Unencrypted file-transfer traffic may expose data."),
    21: ("FTP", "high", "FTP can expose credentials and data in plaintext."),
    22: ("SSH", "low", "Confirm that remote administration is authorised and hardened."),
    23: ("Telnet", "high", "Telnet transmits credentials and sessions without encryption."),
    25: ("SMTP", "medium", "Review mail-relay configuration and external exposure."),
    53: ("DNS", "low", "Verify that DNS recursion and zone transfers are restricted."),
    67: ("DHCP Server", "low", "Confirm that only authorised DHCP servers are present."),
    68: ("DHCP Client", "low", "Expected on DHCP clients but should be inventoried."),
    80: ("HTTP", "medium", "HTTP is unencrypted; confirm redirects or approved use."),
    110: ("POP3", "high", "POP3 can expose email credentials without encryption."),
    123: ("NTP", "low", "Verify that the service is patched and amplification is restricted."),
    135: ("Microsoft RPC", "medium", "Restrict RPC exposure to trusted network segments."),
    137: ("NetBIOS Name", "medium", "NetBIOS may disclose host and domain information."),
    138: ("NetBIOS Datagram", "medium", "Review legacy NetBIOS requirements."),
    139: ("NetBIOS Session", "high", "Legacy file-sharing exposure requires review."),
    143: ("IMAP", "medium", "Prefer encrypted IMAPS where possible."),
    161: ("SNMP", "high", "Default or weak community strings may expose device information."),
    389: ("LDAP", "medium", "Review anonymous binding and prefer encrypted LDAP."),
    443: ("HTTPS", "low", "Review certificate validity and application security."),
    445: ("SMB", "high", "SMB exposure can enable lateral movement and file-share access."),
    465: ("SMTPS", "low", "Verify certificate and authentication configuration."),
    514: ("Syslog", "medium", "Unencrypted syslog may expose sensitive event data."),
    587: ("Mail Submission", "low", "Confirm authentication and encryption requirements."),
    636: ("LDAPS", "low", "Verify certificate trust and directory access controls."),
    993: ("IMAPS", "low", "Verify certificate and authentication controls."),
    995: ("POP3S", "low", "Verify certificate and authentication controls."),
    1433: ("Microsoft SQL Server", "high", "Database services should be tightly restricted."),
    1521: ("Oracle Database", "high", "Database exposure requires strict access control."),
    2049: ("NFS", "high", "Review exported shares and client restrictions."),
    3306: ("MySQL", "high", "Databases should not be broadly reachable."),
    3389: ("Remote Desktop", "high", "RDP exposure requires MFA, patching, and access controls."),
    5432: ("PostgreSQL", "high", "Restrict database access to approved application hosts."),
    5900: ("VNC", "high", "Remote desktop exposure requires strong authentication."),
    6379: ("Redis", "high", "Unauthenticated Redis exposure can lead to compromise."),
    8080: ("HTTP Alternate", "medium", "Review the web service and administrative interfaces."),
    8443: ("HTTPS Alternate", "medium", "Review certificates and administrative exposure."),
    9200: ("Elasticsearch", "high", "Unrestricted access can expose or modify indexed data."),
    27017: ("MongoDB", "high", "Verify authentication and network restrictions.")
}

PORT_REMEDIATIONS = {
    20: "Replace FTP with SFTP or another encrypted transfer method.",
    21: "Disable FTP if unused; otherwise restrict clients and migrate to SFTP.",
    22: "Restrict source addresses, require key authentication, and disable direct root login.",
    23: "Disable Telnet and replace it with SSH.",
    25: "Restrict relay permissions and require authenticated, encrypted mail submission.",
    53: "Limit recursion and zone transfers to authorised systems.",
    67: "Confirm the DHCP server is authorised and enable network-level DHCP protections.",
    68: "Confirm the client listener is expected and managed.",
    80: "Redirect to HTTPS or document the approved reason for unencrypted HTTP.",
    110: "Disable plaintext POP3 and migrate clients to POP3S or IMAPS.",
    123: "Patch the service and restrict queries to approved network segments.",
    135: "Limit RPC access with host firewalls and trusted network segmentation.",
    137: "Disable legacy NetBIOS where unnecessary or restrict it to trusted segments.",
    138: "Disable legacy NetBIOS where unnecessary or restrict it to trusted segments.",
    139: "Disable SMB over NetBIOS if unused and restrict file-sharing access.",
    143: "Require encrypted IMAP and disable plaintext authentication.",
    161: "Use SNMPv3, remove default community strings, and restrict management sources.",
    389: "Restrict directory access and prefer LDAPS for sensitive authentication traffic.",
    443: "Validate TLS configuration, certificates, patch status, and application access controls.",
    445: "Restrict SMB to trusted hosts, disable SMBv1, patch systems, and review share permissions.",
    465: "Validate certificates and require authenticated mail submission.",
    514: "Restrict log receivers and use encrypted transport where supported.",
    587: "Require authentication, TLS, and approved sender policies.",
    636: "Validate certificate trust and apply least-privilege directory permissions.",
    993: "Validate TLS and enforce strong account authentication.",
    995: "Validate TLS and enforce strong account authentication.",
    1433: "Allow only approved application hosts and enforce database authentication.",
    1521: "Restrict listener access, patch the database, and enforce least privilege.",
    2049: "Restrict exported shares to approved clients and review mount permissions.",
    3306: "Bind to required interfaces only and allow approved application hosts.",
    3389: "Require MFA or a secured gateway, restrict sources, and apply current patches.",
    5432: "Restrict database access to approved hosts and review pg_hba.conf rules.",
    5900: "Restrict VNC access, require strong authentication, and use encrypted tunnelling.",
    6379: "Require authentication, bind privately, and restrict access with firewall rules.",
    8080: "Identify the application, restrict administrative interfaces, and apply HTTPS where possible.",
    8443: "Validate TLS, identify the application, and restrict administrative access.",
    9200: "Require authentication and restrict Elasticsearch access to approved clients.",
    27017: "Enable authentication and restrict MongoDB access to approved application hosts."
}


@dataclass(frozen=True)
class ScanRequest:
    network: ipaddress.IPv4Network
    ports: tuple[int, ...]
    timeout: float


def validate_target(target: str) -> ipaddress.IPv4Network:
    cleaned_target = target.strip()

    if not cleaned_target:
        raise ValueError("Enter a target IP address or private CIDR range.")

    try:
        network = ipaddress.ip_network(cleaned_target, strict=False)
    except ValueError as error:
        raise ValueError("Enter a valid IPv4 address or CIDR range.") from error

    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("PortProof currently supports IPv4 targets only.")

    if not any(network.subnet_of(allowed) for allowed in ALLOWED_NETWORKS):
        raise ValueError(
            "Only localhost and RFC1918 private networks are permitted."
        )

    if network.num_addresses > 256:
        raise ValueError("Network ranges larger than /24 are not permitted.")

    return network


def parse_custom_ports(value: str) -> tuple[int, ...]:
    if not value.strip():
        raise ValueError("Enter at least one custom port.")

    parsed_ports: set[int] = set()

    for item in value.split(","):
        item = item.strip()

        if not item:
            continue

        if "-" in item:
            parts = item.split("-", maxsplit=1)

            if len(parts) != 2:
                raise ValueError(f"Invalid port range: {item}")

            try:
                start, end = (int(part.strip()) for part in parts)
            except ValueError as error:
                raise ValueError(f"Invalid port range: {item}") from error

            if start > end:
                raise ValueError(f"Port range begins after it ends: {item}")

            parsed_ports.update(range(start, end + 1))
        else:
            try:
                parsed_ports.add(int(item))
            except ValueError as error:
                raise ValueError(f"Invalid port: {item}") from error

    if not parsed_ports:
        raise ValueError("Enter at least one valid custom port.")

    if any(port < 1 or port > 65535 for port in parsed_ports):
        raise ValueError("Ports must be between 1 and 65535.")

    if len(parsed_ports) > 128:
        raise ValueError("Custom scans are limited to 128 ports.")

    return tuple(sorted(parsed_ports))


def build_scan_request(
    target: str,
    profile: str,
    custom_ports: str,
    timeout: float
) -> ScanRequest:
    network = validate_target(target)

    if profile == "common":
        ports = COMMON_PORTS
    elif profile == "extended":
        if network.num_addresses > 1:
            raise ValueError(
                "The 1–1024 extended scan is limited to a single host."
            )
        ports = tuple(range(1, 1025))
    elif profile == "custom":
        ports = parse_custom_ports(custom_ports)
    else:
        raise ValueError("Select a recognised scan profile.")

    safe_timeout = max(0.1, min(float(timeout), 2.0))

    return ScanRequest(
        network=network,
        ports=ports,
        timeout=safe_timeout
    )


def iter_hosts(network: ipaddress.IPv4Network) -> Iterable[str]:
    if network.num_addresses == 1:
        yield str(network.network_address)
        return

    for host in network.hosts():
        yield str(host)


def scan_port(host: str, port: int, timeout: float) -> dict | None:
    started_at = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            result = client.connect_ex((host, port))

        if result != 0:
            return None

        elapsed_ms = round((time.perf_counter() - started_at) * 1000, 2)
        service, severity, explanation = PORT_CATALOG.get(
            port,
            (service_name(port), "informational", "Open service requires validation.")
        )
        remediation = PORT_REMEDIATIONS.get(
            port,
            "Identify the listening application, confirm business need, and restrict access."
        )

        return {
            "host": host,
            "port": port,
            "service": service,
            "severity": severity,
            "explanation": explanation,
            "remediation": remediation,
            "service_confidence": "Inferred from the standard TCP port; validate the application.",
            "response_ms": elapsed_ms
        }
    except (OSError, socket.timeout):
        return None


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "Unknown TCP Service"


def resolve_hostname(host: str) -> str:
    try:
        return socket.gethostbyaddr(host)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "Unresolved"


def scan_network(scan_request: ScanRequest) -> dict:
    started_at = time.perf_counter()
    hosts = tuple(iter_hosts(scan_request.network))
    total_checks = len(hosts) * len(scan_request.ports)

    findings: list[dict] = []

    with ThreadPoolExecutor(max_workers=48) as executor:
        futures = {
            executor.submit(
                scan_port,
                host,
                port,
                scan_request.timeout
            ): (host, port)
            for host in hosts
            for port in scan_request.ports
        }

        for future in as_completed(futures):
            finding = future.result()

            if finding:
                findings.append(finding)

    findings.sort(key=lambda item: (ipaddress.ip_address(item["host"]), item["port"]))

    grouped_hosts: dict[str, dict] = {}

    for finding in findings:
        host = finding["host"]

        if host not in grouped_hosts:
            grouped_hosts[host] = {
                "ip": host,
                "hostname": resolve_hostname(host),
                "open_ports": []
            }

        grouped_hosts[host]["open_ports"].append(finding)

    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0
    }

    for finding in findings:
        severity_counts[finding["severity"]] += 1

    elapsed_seconds = round(time.perf_counter() - started_at, 2)

    return {
        "target": str(scan_request.network),
        "hosts_checked": len(hosts),
        "ports_checked_per_host": len(scan_request.ports),
        "total_connection_checks": total_checks,
        "hosts_with_open_ports": len(grouped_hosts),
        "open_port_count": len(findings),
        "severity_counts": severity_counts,
        "duration_seconds": elapsed_seconds,
        "hosts": list(grouped_hosts.values()),
        "findings": findings
    }
