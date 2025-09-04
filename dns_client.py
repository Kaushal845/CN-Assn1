#!/usr/bin/env python3
"""
dns_client.py

Streams a large PCAP using scapy.PcapReader (memory efficient), filters DNS queries,
prepends an 8-byte header HHMMSSID (ID is two-digit sequence starting 00),
sends to server framed by 2-byte length prefix, receives server JSON reply,
and writes a CSV report with columns: header, domain, resolved_ip
"""
import sys
import socket
import struct
import datetime
import csv
from scapy.all import PcapReader, DNS
import json

# ---- framing helpers ----
def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!H", len(payload)) + payload)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 2)
    (length,) = struct.unpack("!H", header)
    data = recv_exact(sock, length)
    return data

# ---- header builder ----
def make_header(seq_id: int, when: datetime.datetime = None) -> str:
    when = when or datetime.datetime.now()
    hh = f"{when:%H}"
    mm = f"{when:%M}"
    ss = f"{when:%S}"
    id_ = f"{seq_id % 100:02d}"   # two-digit session id (wrap at 100)
    return f"{hh}{mm}{ss}{id_}"

# ---- run client ----
def run_client(pcap_path: str, server_host: str = "127.0.0.1", server_port: int = 53530,
               report_csv: str = "report.csv", skip_local: bool = False):
    print(f"[*] Streaming PCAP: {pcap_path}")
    seq_id = 0
    rows = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))
        print(f"[*] Connected to server {server_host}:{server_port}")

        with PcapReader(pcap_path) as pcap:
            packet_count = 0
            for pkt in pcap:
                packet_count += 1
                # quick progress log every 100k packets
                if packet_count % 100000 == 0:
                    print(f"[*] processed {packet_count} packets, sent {seq_id} queries so far...")

                # filter DNS queries only (qr==0)
                try:
                    if not pkt.haslayer(DNS):
                        continue
                    dns_layer = pkt[DNS]
                    if dns_layer.qr != 0:
                        continue
                except Exception:
                    continue

                # extract qname if possible
                qname = ""
                try:
                    if dns_layer.qdcount > 0 and dns_layer.qd is not None:
                        raw_q = dns_layer.qd.qname
                        qname = raw_q.decode() if isinstance(raw_q, bytes) else str(raw_q)
                except Exception:
                    qname = ""

                # optional: skip .local queries which are mDNS and not resolvable by rules if desired
                if skip_local and qname.endswith(".local."):
                    # still increment the seq_id? For consistent IDs as per "sequence of DNS query starting from 00",
                    # we will increment only for forwarded queries so the ID reflects forwarded queries count.
                    continue

                header = make_header(seq_id)
                dns_bytes = bytes(dns_layer)   # raw DNS bytes
                payload = header.encode("ascii") + dns_bytes

                # send and wait for response
                try:
                    send_frame(s, payload)
                except Exception as e:
                    print(f"[!] send_frame error: {e}")
                    break

                # receive response
                try:
                    resp = recv_frame(s)
                except Exception as e:
                    print(f"[!] recv_frame error: {e}")
                    break

                # parse response: header + JSON
                if len(resp) < 8:
                    print("[!] malformed response (too short)")
                    continue
                resp_header = resp[:8].decode("ascii", errors="ignore")
                try:
                    resp_json = json.loads(resp[8:].decode("utf-8", errors="ignore"))
                except Exception:
                    resp_json = {"id": resp_header, "qname": qname, "resolved": ""}

                resolved_ip = resp_json.get("resolved", "")
                print(f"[{seq_id:02d}] {resp_header} {qname} -> {resolved_ip}")

                # log for report
                rows.append((resp_header, qname, resolved_ip))

                seq_id += 1

    # write report CSV
    with open(report_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["custom_header(HHMMSSID)", "domain", "resolved_ip"])
        for r in rows:
            writer.writerow(r)
    print(f"[*] Done. wrote {len(rows)} rows to {report_csv}")

# ---- CLI ----
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python dns_client.py <pcap_path> <server_ip> [server_port] [report.csv] [skip_local(0|1)]")
        sys.exit(1)
    pcap_path = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = int(sys.argv[3]) if len(sys.argv) > 3 else 53530
    report_csv = sys.argv[4] if len(sys.argv) > 4 else "report.csv"
    skip_local = bool(int(sys.argv[5])) if len(sys.argv) > 5 else False

    run_client(pcap_path, server_ip, server_port, report_csv, skip_local)
