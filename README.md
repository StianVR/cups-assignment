# CUPS Printer Discovery Lab

A small Scapy-based lab for testing legacy CUPS printer discovery and detecting suspicious advertisements. Use only with the isolated Vulhub Docker environment; do not target public or third-party systems.

## Lab

- Attacker: Ubuntu 24.04, Python 3.12, Scapy 2.8.0, tcpdump
- Victim: Vulhub `cups-browsed` 2.0.1 / CUPS 2.4.7
- Virtual printer: `ippeveprinter` with Avahi, normally at `172.19.0.2:8631`
- CUPS is mapped to host loopback on UDP/TCP 631. Container IPs can change; check them with `docker compose ps` and `docker compose exec cups getent hosts ipp-printer`.

Start the Vulhub lab from its `CVE-2024-47177` directory:

```bash
docker compose up -d
```

See the [Vulhub lab](https://github.com/vulhub/vulhub/tree/master/cups-browsed/CVE-2024-47177) for its setup. The directory keeps the CVE-2024-47177 name; this project tests the printer-discovery behavior described in the assignment.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Scapy packet sending may require root privileges. Run commands from the repository root so output paths resolve correctly.

## Attack tool

`cups_attack.py` builds and sends a UDP CUPS browse advertisement, logs it, and saves the sent packet to PCAP. Example for the local lab:

```bash
sudo .venv/bin/python cups_attack.py \
  --target 127.0.0.1 \
  --printer-uri http://172.19.0.2:8631/printers/ScapyLab \
  --pcap pcap_files/task2_attack.pcap \
  --log-file evidence/task2_attack.log
```

Use `--help` to see options for printer URI, location, description, state, type, target, and port. The experiments varied the URI path, IPP port, state, and metadata. The `/printers/ScapyLab` example caused CUPS to contact the simulator, but the simulator returned `client-error-not-found`; it did not create a usable print queue.

## Detector

`cups_detector.py` analyzes a PCAP offline and writes alerts to CSV and JSON. Example:

```bash
python cups_detector.py \
  --pcap pcap_files/task2_full_flow.pcap \
  --allow-ip 172.19.0.2 \
  --ipp-ports 631 8631 8632 \
  --csv evidence/task2_alerts.csv \
  --json evidence/task2_alerts.json
```

Rules cover unapproved CUPS and mDNS printer advertisements, malformed browse messages, unexpected URI paths and ports, repeated discovery messages, and TCP IPP connection attempts. `--allow-ip` may be repeated for multiple authorized printer addresses. Synthetic PCAPs in `pcap_files/` exercise repeat, malformed-message, and suspicious-connection rules; they are labeled synthetic evidence.

## Evidence and mitigation

- `pcap_files/` contains normal discovery, crafted advertisements, attack-flow, synthetic detector, and before/after mitigation captures.
- `evidence/` contains logs and CSV/JSON detector results. Add screenshots under `evidence/screenshots/` and caption which experiment each one supports.
- The tested mitigation changed `BrowseRemoteProtocols dnssd cups` to `BrowseRemoteProtocols dnssd` and restarted `cups-browsed`. In this lab, the legacy UDP advertisement remained visible on the network but no longer triggered an IPP connection. This tests that discovery path only; it does not establish that every CUPS vulnerability is fixed.

## Results and limits

The victim accepted crafted discovery fields and initiated IPP communication in the tested cases. Some advertised endpoints did not match the simulator or had no listener, so no usable queue was created. The detector is offline and rule-based; results depend on the configured allowlist and monitored ports. The project demonstrates discovery and detection behavior, not a general remote-code-execution claim.
