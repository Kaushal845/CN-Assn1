import sys
import socket
import struct
import datetime
import csv
from scapy.all import PcapReader, DNS  # Using PCAPreader instead og rdpcap as pcap file is large.
import json

# Framing helpers
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

# Header builder
def make_header(seq_id: int, when: datetime.datetime = None) -> str:
    when = when or datetime.datetime.now()
    hh = f"{when:%H}"
    mm = f"{when:%M}"
    ss = f"{when:%S}"
    id_ = f"{seq_id % 100:02d}"   # two-digit session id
    return f"{hh}{mm}{ss}{id_}"

# Run client
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

                # filter DNS queries only i.e. qr == 0
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

                # skip .local queries which are mDNS and not resolvable by rules if desired
                if skip_local and qname.endswith(".local."):
                    continue

                header = make_header(seq_id)
                dns_bytes = bytes(dns_layer)   # raw DNS bytes
                payload = header.encode("ascii") + dns_bytes

                # send and wait
                try:
                    send_frame(s, payload)
                except Exception as e:
                    print(f"[!] send_frame error: {e}")
                    break

                # receive
                try:
                    resp = recv_frame(s)
                except Exception as e:
                    print(f"[!] recv_frame error: {e}")
                    break

                # parsing response - header + JSON
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

                rows.append((resp_header, qname, resolved_ip))

                seq_id += 1

    # write report CSV
    with open(report_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["custom_header(HHMMSSID)", "domain", "resolved_ip"])
        for r in rows:
            writer.writerow(r)
    print(f"[*] Done. wrote {len(rows)} rows to {report_csv}")


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
