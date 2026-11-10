#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from scapy.all import IP, UDP, TCP, PcapReader

BROWSE_RE = re.compile(
    r'^(?P<ptype>[0-9a-fA-F]+)\s+'
    r'(?P<state>[0-9a-fA-F]+)\s+'
    r'(?P<uri>\S+)\s+'
    r'"(?P<location>[^"]*)"\s+'
    r'"(?P<info>[^"]*)"$'
)

FIELDS = ["timestamp", "severity", "alert", "src", "dst", "details"]


def main():
    parser = argparse.ArgumentParser(
        description="Detect suspicious CUPS printer discovery and IPP traffic in a PCAP."
    )
    parser.add_argument("--pcap", required=True, help="Input PCAP file")
    parser.add_argument(
        "--allow-ip", action="append", default=[],
        help="Authorized printer IP; repeat for multiple printers"
    )
    parser.add_argument(
        "--ipp-ports", nargs="+", type=int, default=[631, 8631],
        help="IPP ports to monitor (default: 631 8631)"
    )
    parser.add_argument("--repeat-count", type=int, default=5)
    parser.add_argument("--window", type=float, default=10,
                        help="Repeat-detection window in seconds")
    parser.add_argument("--csv", default="evidence/task3_alerts.csv")
    parser.add_argument("--json", default="evidence/task3_alerts.json")
    args = parser.parse_args()

    allowed_ips = set(args.allow_ip)
    repeated = defaultdict(deque)
    alerts = []
    packet_count = 0

    def add_alert(ts, severity, name, src, dst, details):
        alerts.append({
            "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
            "severity": severity,
            "alert": name,
            "src": src,
            "dst": dst,
            "details": details,
        })

    def check_repeat(ts, src):
        times = repeated[src]
        while times and ts - times[0] > args.window:
            times.popleft()
        times.append(ts)
        if len(times) == args.repeat_count:
            add_alert(
                ts, "MEDIUM", "REPEATED_DISCOVERY", src, "",
                f"{len(times)} discovery messages within {args.window:g} seconds",
            )

    with PcapReader(args.pcap) as capture:
        for pkt in capture:
            packet_count += 1
            if IP not in pkt:
                continue

            ts = float(pkt.time)
            src, dst = pkt[IP].src, pkt[IP].dst

            if UDP in pkt:
                udp = pkt[UDP]
                payload = bytes(udp.payload)
                lower_payload = payload.lower()

                # Legacy CUPS browse announcement.
                if udp.dport == 631:
                    check_repeat(ts, src)

                    if src not in allowed_ips:
                        add_alert(
                            ts, "HIGH", "UNAUTHORIZED_CUPS_ADVERTISEMENT",
                            src, dst, "Browse datagram from an unapproved source",
                        )

                    text = payload.decode("utf-8", errors="replace").strip()
                    match = BROWSE_RE.fullmatch(text)

                    if not match:
                        add_alert(
                            ts, "MEDIUM", "MALFORMED_BROWSE_PACKET",
                            src, dst, f"Unexpected browse payload: {text[:160]}",
                        )
                    else:
                        uri = match.group("uri")
                        parsed = urlsplit(uri)

                        if parsed.scheme.lower() not in {"http", "https", "ipp", "ipps"} \
                                or not parsed.hostname:
                            add_alert(
                                ts, "MEDIUM", "UNEXPECTED_URI",
                                src, dst, f"Unexpected printer URI: {uri}",
                            )
                        elif not parsed.path.startswith("/printers/"):
                            add_alert(
                                ts, "MEDIUM", "UNEXPECTED_PRINTER_PATH",
                                src, dst, f"Browse URI path is {parsed.path!r}",
                            )

                        try:
                            uri_port = parsed.port
                        except ValueError:
                            uri_port = -1

                        if uri_port == -1 or (
                            uri_port is not None and uri_port not in args.ipp_ports
                        ):
                            add_alert(
                                ts, "MEDIUM", "UNEXPECTED_PRINTER_PORT",
                                src, dst, f"Printer URI uses port {uri_port}",
                            )

                        if parsed.hostname:
                            try:
                                uri_ip = str(ipaddress.ip_address(parsed.hostname))
                                if uri_ip not in allowed_ips:
                                    add_alert(
                                        ts, "HIGH", "UNAUTHORIZED_ADVERTISED_PRINTER",
                                        src, uri_ip, f"Advertisement URI: {uri}",
                                    )
                            except ValueError:
                                pass

                # DNS-SD/mDNS printer advertisement.
                if (udp.sport == 5353 or udp.dport == 5353) \
                        and b"_ipp" in lower_payload and b"_tcp" in lower_payload:
                    check_repeat(ts, src)
                    if src not in allowed_ips:
                        add_alert(
                            ts, "HIGH", "UNAUTHORIZED_MDNS_PRINTER_AD",
                            src, dst, "mDNS payload advertises an IPP service",
                        )

            # Record IPP connection attempts; flag destinations outside the allowlist.
            if TCP in pkt:
                tcp = pkt[TCP]
                if tcp.dport in args.ipp_ports and int(tcp.flags) & 0x02:
                    if dst not in allowed_ips:
                        add_alert(
                            ts, "HIGH", "SUSPICIOUS_IPP_CONNECTION",
                            src, dst, f"TCP connection attempt to port {tcp.dport}",
                        )
                    else:
                        add_alert(
                            ts, "INFO", "IPP_CONNECTION_OBSERVED",
                            src, dst, f"TCP connection attempt to allowed port {tcp.dport}",
                        )

    for output in (args.csv, args.json):
        Path(output).parent.mkdir(parents=True, exist_ok=True)

    with open(args.csv, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(alerts)

    with open(args.json, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=2)

    print(f"Analyzed {packet_count} packets; generated {len(alerts)} alerts.")
    for alert in alerts:
        print(
            f'{alert["severity"]}: {alert["alert"]} '
            f'{alert["src"]} -> {alert["dst"]}: {alert["details"]}'
        )
    print(f"CSV:  {args.csv}")
    print(f"JSON: {args.json}")


if __name__ == "__main__":
    main()
