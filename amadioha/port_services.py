"""Port to service name mapping utility."""

from typing import List, Dict

# Common port mappings based on IANA service registry
PORT_SERVICES = {
    1: "TCPMUX",
    7: "Echo",
    9: "Discard",
    11: "Systat",
    13: "Daytime",
    15: "Netstat",
    17: "QOTD",
    19: "Chargen",
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "Time Protocol",
    42: "Name",
    43: "Whois",
    49: "Tacacs",
    50: "Re-mail-ck",
    53: "DNS",
    57: "Priv-Print",
    67: "DHCP/Bootps",
    68: "DHCP/Bootpc",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos",
    101: "NIC-Host",
    102: "ISO-TSAP",
    103: "X400",
    104: "X400-SND",
    109: "POP2",
    110: "POP3",
    111: "Sun-RPC",
    113: "Ident",
    115: "SFTP",
    117: "Uucp-Path",
    119: "NNTP",
    123: "NTP",
    135: "RPC Endpoint Mapper",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMPTRAP",
    177: "XDMCP",
    179: "BGP",
    199: "SMUX",
    220: "IMAP3",
    389: "LDAP",
    427: "SLP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "ISAKMP",
    514: "Syslog",
    515: "LPD",
    543: "Klogin",
    544: "Kshell",
    587: "SMTP-TLS",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5500: "VNC",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Alternate HTTP",
    9200: "Elasticsearch",
    27017: "MongoDB",
    50070: "Hadoop NameNode",
}


def get_service_name(port: int) -> str:
    """Get the service name for a given port."""
    return PORT_SERVICES.get(port, "Unknown")


def get_service_info(port: int) -> Dict[str, str]:
    """Get detailed service information for a port."""
    service_name = PORT_SERVICES.get(port, "Unknown")
    return {
        "port": port,
        "service": service_name,
        "protocol": "TCP"
    }


def enrich_scan_results(open_ports: List[int]) -> List[Dict]:
    """Enrich scan results with service names."""
    enriched = []
    for port in open_ports:
        enriched.append({
            "port": port,
            "service": get_service_name(port)
        })
    return enriched


if __name__ == "__main__":
    # Test
    test_ports = [22, 80, 443, 3306, 5432]
    for port_info in enrich_scan_results(test_ports):
        print(f"Port {port_info['port']}: {port_info['service']}")
